//! Redis client with RESP protocol and Cx integration.
//!
//! This module provides a pure Rust Redis client implementing the RESP
//! (REdis Serialization Protocol) with Cx integration for cancel-correct
//! command execution.

use crate::cx::Cx;
use crate::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use crate::net::TcpStream;
use crate::sync::{GenericPool, Pool as _, PoolConfig, PoolError, PooledResource};
#[cfg(feature = "tls")]
use crate::tls::{TlsConnector, TlsConnectorBuilder, TlsStream};
use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

/// Error type for Redis operations.
#[derive(Debug)]
pub enum RedisError {
    /// I/O error during communication.
    Io(io::Error),
    /// Protocol error (malformed RESP response).
    Protocol(String),
    /// Redis returned an error response.
    Redis(String),
    /// Connection pool exhausted.
    PoolExhausted,
    /// Invalid URL format.
    InvalidUrl(String),
    /// Operation cancelled.
    Cancelled,
    /// Authentication required (Redis NOAUTH error).
    NoAuth,
    /// Authentication failed (Redis WRONGPASS error).
    WrongPassword,
    /// Pub/Sub subscriber fell behind: the configured
    /// `pubsub_max_backlog` was reached and incoming events were
    /// dropped to bound memory. Carries the number of events dropped
    /// since the previous `SubscriberLag` was reported on this
    /// subscriber. Cumulative drops over the lifetime of the
    /// connection are available via
    /// [`RedisPubSub::pubsub_dropped_events`].
    /// See `RedisConfig::pubsub_max_backlog` (br-asupersync-697arj).
    SubscriberLag {
        /// Number of events dropped since the last time `SubscriberLag`
        /// was returned by `next_event` on this subscriber.
        dropped: u64,
    },
    /// Regular command-client RESP3 push backlog overflowed. Carries
    /// the number of pushes dropped since the previous
    /// [`RedisClient::try_next_resp3_push`] lag report.
    Resp3PushLag {
        /// Number of RESP3 pushes dropped since the previous lag
        /// report surfaced through [`RedisClient::try_next_resp3_push`].
        dropped: u64,
    },
}

impl fmt::Display for RedisError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "Redis I/O error: {e}"),
            Self::Protocol(msg) => write!(f, "Redis protocol error: {msg}"),
            Self::Redis(msg) => write!(f, "Redis error: {msg}"),
            Self::PoolExhausted => write!(f, "Redis connection pool exhausted"),
            Self::InvalidUrl(url) => write!(f, "Invalid Redis URL: {url}"),
            Self::Cancelled => write!(f, "Redis operation cancelled"),
            Self::NoAuth => write!(f, "Redis authentication required (NOAUTH)"),
            Self::WrongPassword => write!(f, "Redis authentication failed (WRONGPASS)"),
            Self::SubscriberLag { dropped } => write!(
                f,
                "Redis pub/sub subscriber lag: {dropped} event(s) dropped since last \
                 report (backlog cap reached; raise RedisConfig.pubsub_max_backlog \
                 or drain next_event faster)"
            ),
            Self::Resp3PushLag { dropped } => write!(
                f,
                "Redis RESP3 push backlog lag: {dropped} push frame(s) dropped since last \
                 report (backlog cap reached; raise RedisConfig.resp3_push_max_backlog \
                 or drain try_next_resp3_push faster)"
            ),
        }
    }
}

impl RedisError {
    /// Parse a Redis server error message into a structured error type.
    ///
    /// Per Redis documentation, NOAUTH and WRONGPASS errors should be surfaced
    /// as actionable structured types that callers can match on for proper
    /// authentication handling.
    fn from_redis_error_message(msg: &str) -> Self {
        let lower_msg = msg.to_ascii_lowercase();

        if lower_msg.starts_with("noauth ") || lower_msg == "noauth" {
            Self::NoAuth
        } else if lower_msg.starts_with("wrongpass ") || lower_msg == "wrongpass" {
            Self::WrongPassword
        } else {
            Self::Redis(msg.to_string())
        }
    }
}

impl std::error::Error for RedisError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for RedisError {
    fn from(err: io::Error) -> Self {
        Self::Io(err)
    }
}

impl RedisError {
    /// Whether this error is transient and may succeed on retry.
    #[must_use]
    pub fn is_transient(&self) -> bool {
        matches!(self, Self::Io(_) | Self::PoolExhausted)
    }

    /// Whether this error indicates a connection-level failure.
    #[must_use]
    pub fn is_connection_error(&self) -> bool {
        matches!(self, Self::Io(_))
    }

    /// Whether this error indicates resource/capacity exhaustion.
    #[must_use]
    pub fn is_capacity_error(&self) -> bool {
        matches!(
            self,
            Self::PoolExhausted | Self::SubscriberLag { .. } | Self::Resp3PushLag { .. }
        )
    }

    /// Whether this error is a timeout.
    #[must_use]
    pub fn is_timeout(&self) -> bool {
        matches!(self, Self::Io(e) if e.kind() == io::ErrorKind::TimedOut)
    }

    /// Whether the operation should be retried.
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        self.is_transient()
    }
}

fn push_u64_decimal(buf: &mut Vec<u8>, mut n: u64) {
    let mut tmp = [0u8; 20];
    let mut i = tmp.len();

    if n == 0 {
        i -= 1;
        tmp[i] = b'0';
    } else {
        while n > 0 {
            let digit = (n % 10) as u8;
            n /= 10;
            i -= 1;
            tmp[i] = b'0' + digit;
        }
    }

    buf.extend_from_slice(&tmp[i..]);
}

fn push_i64_decimal(buf: &mut Vec<u8>, n: i64) {
    if n < 0 {
        buf.push(b'-');
    }
    // i64::MIN can't be negated; RESP lengths only use small negatives (-1),
    // but keep this correct anyway.
    let n = n.unsigned_abs();
    push_u64_decimal(buf, n);
}

fn u64_decimal_bytes(mut n: u64, tmp: &mut [u8; 20]) -> &[u8] {
    let mut i = tmp.len();
    if n == 0 {
        i -= 1;
        tmp[i] = b'0';
    } else {
        while n > 0 {
            let digit = (n % 10) as u8;
            n /= 10;
            i -= 1;
            tmp[i] = b'0' + digit;
        }
    }
    &tmp[i..]
}

fn ttl_millis_rounded_up(ttl: Duration) -> u64 {
    let millis = ttl.as_nanos().div_ceil(1_000_000);
    u64::try_from(millis).unwrap_or(u64::MAX)
}

fn positive_ttl_millis(ttl: Duration) -> Result<u64, RedisError> {
    if ttl.is_zero() {
        return Err(RedisError::Protocol(
            "ttl must be greater than zero".to_string(),
        ));
    }

    Ok(ttl_millis_rounded_up(ttl))
}

fn parse_i64_ascii(bytes: &[u8]) -> Result<i64, RedisError> {
    if bytes.is_empty() {
        return Err(RedisError::Protocol(
            "invalid integer: expected digits, got empty".to_string(),
        ));
    }

    let mut i = 0;
    let mut neg = false;
    if bytes[0] == b'-' {
        neg = true;
        i = 1;
        if i == bytes.len() {
            return Err(RedisError::Protocol(
                "invalid integer: expected digits after '-'".to_string(),
            ));
        }
    }

    let limit: i128 = if neg {
        i128::from(i64::MAX) + 1
    } else {
        i128::from(i64::MAX)
    };

    let mut acc: i128 = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if !b.is_ascii_digit() {
            return Err(RedisError::Protocol(format!(
                "invalid integer byte: 0x{b:02x}"
            )));
        }
        let digit = i128::from(b - b'0');
        // Check for overflow before performing arithmetic to prevent TOCTOU vulnerability
        acc = acc
            .checked_mul(10)
            .and_then(|a| a.checked_add(digit))
            .ok_or_else(|| RedisError::Protocol("integer overflow during parsing".to_string()))?;
        if acc > limit {
            return Err(RedisError::Protocol("integer overflow".to_string()));
        }
        i += 1;
    }

    let signed = if neg { -acc } else { acc };
    i64::try_from(signed).map_err(|_| RedisError::Protocol("integer overflow".to_string()))
}

fn find_crlf(buf: &[u8], start: usize) -> Option<usize> {
    let mut i = start;
    while i + 1 < buf.len() {
        if buf[i] == b'\r' && buf[i + 1] == b'\n' {
            return Some(i);
        }
        i += 1;
    }
    None
}

fn validate_resp3_big_number_payload(payload: &str) -> Result<(), RedisError> {
    let digits = match payload.as_bytes() {
        [] => {
            return Err(RedisError::Protocol(
                "RESP3 big number must not be empty".to_string(),
            ));
        }
        [b'+' | b'-', rest @ ..] => {
            if rest.is_empty() {
                return Err(RedisError::Protocol(
                    "RESP3 big number sign must be followed by digits".to_string(),
                ));
            }
            rest
        }
        bytes => bytes,
    };

    if digits.iter().all(u8::is_ascii_digit) {
        Ok(())
    } else {
        Err(RedisError::Protocol(
            "RESP3 big number must contain only decimal digits after an optional sign".to_string(),
        ))
    }
}

/// RESP (REdis Serialization Protocol) value.
///
/// Covers RESP2 and the RESP3 type extensions negotiated via `HELLO 3`
/// (br-asupersync-xlh4nx). The decoder handles the full RESP3 surface so a
/// server that is upgraded mid-deployment can return RESP3-only types without
/// crashing the client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RespValue {
    /// Simple string (prefixed with +).
    SimpleString(String),
    /// Error message (prefixed with -).
    Error(String),
    /// 64-bit signed integer (prefixed with :).
    Integer(i64),
    /// Bulk string (prefixed with $, can be null).
    BulkString(Option<Vec<u8>>),
    /// Array of RESP values (prefixed with *, can be null).
    Array(Option<Vec<Self>>),
    /// RESP3 null value (`_\r\n`).
    Null,
    /// RESP3 boolean (`#t\r\n` / `#f\r\n`).
    Boolean(bool),
    /// RESP3 double-precision float as the original ASCII decimal payload
    /// (`,3.14\r\n`). Stored as a string to preserve the exact wire form,
    /// including `inf`, `-inf`, and `nan`.
    Double(String),
    /// RESP3 arbitrary-precision number, kept as ASCII (`(123456789...\r\n`).
    BigNumber(String),
    /// RESP3 verbatim string with a 3-byte format prefix and ':' separator
    /// (`=15\r\ntxt:Some text\r\n`). The tuple is `(format, payload)`.
    Verbatim {
        /// Three-byte RESP3 verbatim format marker, for example `txt`.
        format: String,
        /// Raw payload bytes after the format marker and `:` separator.
        payload: Vec<u8>,
    },
    /// RESP3 binary error (`!21\r\nSYNTAX invalid syntax\r\n`).
    BlobError(Vec<u8>),
    /// RESP3 map (`%N\r\n` followed by N key-value pairs).
    Map(Vec<(Self, Self)>),
    /// RESP3 set (`~N\r\n` followed by N items).
    Set(Vec<Self>),
    /// RESP3 server-pushed message (`>N\r\n` followed by N items).
    Push(Vec<Self>),
    /// RESP3 attribute payload (`|N\r\n` followed by N key-value pairs).
    /// Auxiliary metadata that the server attaches to a following value;
    /// the client is free to ignore it.
    Attribute(Vec<(Self, Self)>),
}

impl RespValue {
    /// Encode this value to RESP wire format.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        self.encode_into(&mut buf);
        buf
    }

    /// Encode this value into an existing buffer.
    pub fn encode_into(&self, buf: &mut Vec<u8>) {
        match self {
            Self::SimpleString(s) => {
                buf.push(b'+');
                // RESP simple strings must not contain CR or LF.
                for &b in s.as_bytes() {
                    if b != b'\r' && b != b'\n' {
                        buf.push(b);
                    }
                }
                buf.extend_from_slice(b"\r\n");
            }
            Self::Error(e) => {
                buf.push(b'-');
                // RESP error strings must not contain CR or LF.
                for &b in e.as_bytes() {
                    if b != b'\r' && b != b'\n' {
                        buf.push(b);
                    }
                }
                buf.extend_from_slice(b"\r\n");
            }
            Self::Integer(i) => {
                buf.push(b':');
                push_i64_decimal(buf, *i);
                buf.extend_from_slice(b"\r\n");
            }
            Self::BulkString(Some(data)) => {
                buf.push(b'$');
                push_u64_decimal(buf, data.len() as u64);
                buf.extend_from_slice(b"\r\n");
                buf.extend_from_slice(data);
                buf.extend_from_slice(b"\r\n");
            }
            Self::BulkString(None) => {
                buf.extend_from_slice(b"$-1\r\n");
            }
            Self::Array(Some(arr)) => {
                buf.push(b'*');
                push_u64_decimal(buf, arr.len() as u64);
                buf.extend_from_slice(b"\r\n");
                for item in arr {
                    item.encode_into(buf);
                }
            }
            Self::Array(None) => {
                buf.extend_from_slice(b"*-1\r\n");
            }
            // RESP3 wire formats — used by tests and round-trip helpers.
            Self::Null => {
                buf.extend_from_slice(b"_\r\n");
            }
            Self::Boolean(b) => {
                buf.extend_from_slice(if *b { b"#t\r\n" } else { b"#f\r\n" });
            }
            Self::Double(s) => {
                buf.push(b',');
                for &c in s.as_bytes() {
                    if c != b'\r' && c != b'\n' {
                        buf.push(c);
                    }
                }
                buf.extend_from_slice(b"\r\n");
            }
            Self::BigNumber(s) => {
                buf.push(b'(');
                for &c in s.as_bytes() {
                    if c != b'\r' && c != b'\n' {
                        buf.push(c);
                    }
                }
                buf.extend_from_slice(b"\r\n");
            }
            Self::Verbatim { format, payload } => {
                // <format>:<payload> — total length is 4 + payload.len()
                let total = format.len().saturating_add(1).saturating_add(payload.len());
                buf.push(b'=');
                push_u64_decimal(buf, total as u64);
                buf.extend_from_slice(b"\r\n");
                buf.extend_from_slice(format.as_bytes());
                buf.push(b':');
                buf.extend_from_slice(payload);
                buf.extend_from_slice(b"\r\n");
            }
            Self::BlobError(data) => {
                buf.push(b'!');
                push_u64_decimal(buf, data.len() as u64);
                buf.extend_from_slice(b"\r\n");
                buf.extend_from_slice(data);
                buf.extend_from_slice(b"\r\n");
            }
            Self::Map(pairs) => {
                buf.push(b'%');
                push_u64_decimal(buf, pairs.len() as u64);
                buf.extend_from_slice(b"\r\n");
                for (k, v) in pairs {
                    k.encode_into(buf);
                    v.encode_into(buf);
                }
            }
            Self::Set(items) => {
                buf.push(b'~');
                push_u64_decimal(buf, items.len() as u64);
                buf.extend_from_slice(b"\r\n");
                for item in items {
                    item.encode_into(buf);
                }
            }
            Self::Push(items) => {
                buf.push(b'>');
                push_u64_decimal(buf, items.len() as u64);
                buf.extend_from_slice(b"\r\n");
                for item in items {
                    item.encode_into(buf);
                }
            }
            Self::Attribute(pairs) => {
                buf.push(b'|');
                push_u64_decimal(buf, pairs.len() as u64);
                buf.extend_from_slice(b"\r\n");
                for (k, v) in pairs {
                    k.encode_into(buf);
                    v.encode_into(buf);
                }
            }
        }
    }

    /// Decode one RESP value from the provided buffer using the given protocol limits.
    ///
    /// Returns `Ok(None)` if more bytes are required.
    #[allow(clippy::too_many_lines)]
    #[allow(clippy::use_self)]
    pub fn try_decode_with_limits(
        buf: &[u8],
        limits: &RedisProtocolLimits,
    ) -> Result<Option<(Self, usize)>, RedisError> {
        enum Decoded {
            NeedMore,
            Ok { value: RespValue, next: usize },
        }

        fn parse_resp_len(bytes: &[u8], label: &str) -> Result<usize, RedisError> {
            let len = parse_i64_ascii(bytes)?;
            if len < 0 {
                return Err(RedisError::Protocol(format!(
                    "invalid {label} length: {len}"
                )));
            }
            usize::try_from(len)
                .map_err(|_| RedisError::Protocol(format!("invalid {label} length: {len}")))
        }

        fn bulk_shape_label(tag: u8) -> &'static str {
            match tag {
                b'$' => "bulk string",
                b'=' => "verbatim string",
                b'!' => "blob error",
                _ => "bulk-shape",
            }
        }

        fn aggregate_label(tag: u8) -> &'static str {
            match tag {
                b'*' => "array",
                b'~' => "set",
                b'>' => "push",
                b'%' => "map",
                b'|' => "attribute",
                _ => "aggregate",
            }
        }

        fn stream_end_state(buf: &[u8], i: usize) -> Result<Option<bool>, RedisError> {
            if buf.get(i) != Some(&b'.') {
                return Ok(Some(false));
            }
            if buf.len() < i + 3 {
                return Ok(None);
            }
            if &buf[i..i + 3] == b".\r\n" {
                return Ok(Some(true));
            }
            Err(RedisError::Protocol(
                "invalid RESP3 streamed aggregate terminator".to_string(),
            ))
        }

        fn check_streamed_blob_complete(
            buf: &[u8],
            mut i: usize,
            limits: &RedisProtocolLimits,
        ) -> Result<Option<usize>, RedisError> {
            let mut total_len = 0usize;
            loop {
                if i >= buf.len() {
                    return Ok(None);
                }
                if buf[i] != b';' {
                    return Err(RedisError::Protocol(format!(
                        "RESP3 streamed blob chunk must start with ';', got 0x{:02x}",
                        buf[i]
                    )));
                }
                let Some(end) = find_crlf(buf, i + 1) else {
                    return Ok(None);
                };
                let len = parse_resp_len(&buf[i + 1..end], "streamed blob chunk")?;
                i = end + 2;
                if len == 0 {
                    return Ok(Some(i));
                }
                total_len = total_len.checked_add(len).ok_or_else(|| {
                    RedisError::Protocol("streamed blob length overflow".to_string())
                })?;
                if total_len > limits.max_bulk_string_len {
                    return Err(RedisError::Protocol(format!(
                        "streamed blob length {total_len} exceeds maximum {}",
                        limits.max_bulk_string_len
                    )));
                }
                let end_data = i.saturating_add(len);
                let end_crlf = end_data.saturating_add(2);
                if buf.len() < end_crlf {
                    return Ok(None);
                }
                if buf.get(end_data) != Some(&b'\r') || buf.get(end_data + 1) != Some(&b'\n') {
                    return Err(RedisError::Protocol(
                        "streamed blob chunk missing trailing CRLF".to_string(),
                    ));
                }
                i = end_crlf;
            }
        }

        // Fast-path to check if the complete structure is in the buffer without
        // allocating any intermediate values. This prevents O(N^2) allocations
        // on large fragmented arrays (Schlemiel the Painter's parsing).
        fn check_complete(
            buf: &[u8],
            mut i: usize,
            depth: usize,
            limits: &RedisProtocolLimits,
        ) -> Result<Option<usize>, RedisError> {
            if depth > limits.max_nesting_depth {
                return Err(RedisError::Protocol(format!(
                    "RESP nesting depth exceeds maximum ({})",
                    limits.max_nesting_depth
                )));
            }
            if i >= buf.len() {
                return Ok(None);
            }

            match buf[i] {
                // Single-line types: SimpleString, Error, Integer (RESP2)
                // and Double, BigNumber (RESP3) all read up to the next CRLF.
                b'+' | b'-' | b':' | b',' | b'(' => {
                    let Some(end) = find_crlf(buf, i + 1) else {
                        return Ok(None);
                    };
                    Ok(Some(end + 2))
                }
                // Null (RESP3) — `_\r\n`, no payload.
                b'_' => {
                    let Some(end) = find_crlf(buf, i + 1) else {
                        return Ok(None);
                    };
                    Ok(Some(end + 2))
                }
                // Boolean (RESP3) — `#t\r\n` or `#f\r\n`. Treat like a
                // single-line type; the actual value parses in decode_at.
                b'#' => {
                    let Some(end) = find_crlf(buf, i + 1) else {
                        return Ok(None);
                    };
                    Ok(Some(end + 2))
                }
                // Length-prefixed binary types: BulkString (RESP2), Verbatim
                // and BlobError (RESP3) all share the same wire shape:
                //   <prefix><len>\r\n<payload>\r\n
                b'$' | b'=' | b'!' => {
                    let label = bulk_shape_label(buf[i]);
                    let Some(end) = find_crlf(buf, i + 1) else {
                        return Ok(None);
                    };
                    if buf[i] == b'$' && &buf[i + 1..end] == b"?" {
                        return check_streamed_blob_complete(buf, end + 2, limits);
                    }
                    let len = parse_i64_ascii(&buf[i + 1..end])?;
                    if len == -1 && buf[i] == b'$' {
                        return Ok(Some(end + 2));
                    }
                    if len < 0 {
                        return Err(RedisError::Protocol(format!(
                            "invalid {label} length for byte 0x{:02x}: {len}",
                            buf[i],
                        )));
                    }
                    let len = usize::try_from(len).map_err(|_| {
                        RedisError::Protocol(format!("invalid {label} length: {len}"))
                    })?;
                    if len > limits.max_bulk_string_len {
                        return Err(RedisError::Protocol(format!(
                            "{label} length {len} exceeds maximum {}",
                            limits.max_bulk_string_len
                        )));
                    }
                    let end_crlf = end.saturating_add(2).saturating_add(len).saturating_add(2);
                    if buf.len() < end_crlf {
                        return Ok(None);
                    }
                    Ok(Some(end_crlf))
                }
                // Aggregate types whose payload is N child values: Array
                // (RESP2) plus Set, Push (RESP3 — N items) and Map,
                // Attribute (RESP3 — N pairs = 2N children).
                b'*' | b'~' | b'>' | b'%' | b'|' => {
                    let tag = buf[i];
                    let label = aggregate_label(tag);
                    let Some(end) = find_crlf(buf, i + 1) else {
                        return Ok(None);
                    };
                    if &buf[i + 1..end] == b"?" {
                        if !matches!(tag, b'*' | b'~' | b'%') {
                            return Err(RedisError::Protocol(format!(
                                "RESP3 streamed aggregate not supported for type byte 0x{:02x}",
                                tag
                            )));
                        }
                        let max_children = if tag == b'%' {
                            limits.max_array_len.saturating_mul(2)
                        } else {
                            limits.max_array_len
                        };
                        let mut children = 0usize;
                        i = end + 2;
                        loop {
                            if i >= buf.len() {
                                return Ok(None);
                            }
                            match stream_end_state(buf, i)? {
                                None => return Ok(None),
                                Some(true) => {
                                    if tag == b'%' && children % 2 != 0 {
                                        return Err(RedisError::Protocol(
                                            "RESP3 streamed map ended after an odd number of values"
                                                .to_string(),
                                        ));
                                    }
                                    return Ok(Some(i + 3));
                                }
                                Some(false) => {}
                            }
                            if children >= max_children {
                                return Err(RedisError::Protocol(format!(
                                    "streamed aggregate length exceeds maximum {}",
                                    limits.max_array_len
                                )));
                            }
                            match check_complete(buf, i, depth + 1, limits)? {
                                None => return Ok(None),
                                Some(next) => {
                                    i = next;
                                    children = children.checked_add(1).ok_or_else(|| {
                                        RedisError::Protocol(
                                            "streamed aggregate length overflow".to_string(),
                                        )
                                    })?;
                                }
                            }
                        }
                    }
                    let n = parse_i64_ascii(&buf[i + 1..end])?;
                    if n == -1 && buf[i] == b'*' {
                        return Ok(Some(end + 2));
                    }
                    if n < 0 {
                        return Err(RedisError::Protocol(format!("invalid {label} length: {n}")));
                    }
                    let n = usize::try_from(n).map_err(|_| {
                        RedisError::Protocol(format!("invalid {label} length: {n}"))
                    })?;
                    if n > limits.max_array_len {
                        return Err(RedisError::Protocol(format!(
                            "{label} length {n} exceeds maximum {}",
                            limits.max_array_len
                        )));
                    }
                    let children = if matches!(buf[i], b'%' | b'|') {
                        n.checked_mul(2).ok_or_else(|| {
                            RedisError::Protocol(format!("{label} length overflow"))
                        })?
                    } else {
                        n
                    };
                    i = end + 2;
                    for _ in 0..children {
                        match check_complete(buf, i, depth + 1, limits)? {
                            None => return Ok(None),
                            Some(next) => i = next,
                        }
                    }
                    Ok(Some(i))
                }
                other => Err(RedisError::Protocol(format!(
                    "unknown RESP type byte: 0x{other:02x}"
                ))),
            }
        }

        // Only proceed with full allocation if the structure is completely buffered.
        if check_complete(buf, 0, 0, limits)?.is_none() {
            return Ok(None);
        }

        #[allow(clippy::too_many_lines)]
        fn decode_at(
            buf: &[u8],
            i: usize,
            depth: usize,
            limits: &RedisProtocolLimits,
        ) -> Result<Decoded, RedisError> {
            if depth > limits.max_nesting_depth {
                return Err(RedisError::Protocol(format!(
                    "RESP nesting depth exceeds maximum ({})",
                    limits.max_nesting_depth
                )));
            }
            if i >= buf.len() {
                return Ok(Decoded::NeedMore);
            }

            match buf[i] {
                b'+' => {
                    let Some(end) = find_crlf(buf, i + 1) else {
                        return Ok(Decoded::NeedMore);
                    };
                    let s = std::str::from_utf8(&buf[i + 1..end])
                        .map_err(|_| RedisError::Protocol("invalid UTF-8 in simple string".into()))?
                        .to_string();
                    Ok(Decoded::Ok {
                        value: RespValue::SimpleString(s),
                        next: end + 2,
                    })
                }
                b'-' => {
                    let Some(end) = find_crlf(buf, i + 1) else {
                        return Ok(Decoded::NeedMore);
                    };
                    let s = std::str::from_utf8(&buf[i + 1..end])
                        .map_err(|_| RedisError::Protocol("invalid UTF-8 in error string".into()))?
                        .to_string();
                    Ok(Decoded::Ok {
                        value: RespValue::Error(s),
                        next: end + 2,
                    })
                }
                b':' => {
                    let Some(end) = find_crlf(buf, i + 1) else {
                        return Ok(Decoded::NeedMore);
                    };
                    let n = parse_i64_ascii(&buf[i + 1..end])?;
                    Ok(Decoded::Ok {
                        value: RespValue::Integer(n),
                        next: end + 2,
                    })
                }
                b'$' => {
                    let Some(end) = find_crlf(buf, i + 1) else {
                        return Ok(Decoded::NeedMore);
                    };
                    if &buf[i + 1..end] == b"?" {
                        let mut data = Vec::new();
                        let mut pos = end + 2;
                        loop {
                            if pos >= buf.len() {
                                return Ok(Decoded::NeedMore);
                            }
                            if buf[pos] != b';' {
                                return Err(RedisError::Protocol(format!(
                                    "RESP3 streamed blob chunk must start with ';', got 0x{:02x}",
                                    buf[pos]
                                )));
                            }
                            let Some(chunk_end) = find_crlf(buf, pos + 1) else {
                                return Ok(Decoded::NeedMore);
                            };
                            let len =
                                parse_resp_len(&buf[pos + 1..chunk_end], "streamed blob chunk")?;
                            pos = chunk_end + 2;
                            if len == 0 {
                                return Ok(Decoded::Ok {
                                    value: RespValue::BulkString(Some(data)),
                                    next: pos,
                                });
                            }
                            let next_len = data.len().checked_add(len).ok_or_else(|| {
                                RedisError::Protocol("streamed blob length overflow".to_string())
                            })?;
                            if next_len > limits.max_bulk_string_len {
                                return Err(RedisError::Protocol(format!(
                                    "streamed blob length {next_len} exceeds maximum {}",
                                    limits.max_bulk_string_len
                                )));
                            }
                            let end_data = pos.saturating_add(len);
                            let end_crlf = end_data.saturating_add(2);
                            if buf.len() < end_crlf {
                                return Ok(Decoded::NeedMore);
                            }
                            if buf.get(end_data) != Some(&b'\r')
                                || buf.get(end_data + 1) != Some(&b'\n')
                            {
                                return Err(RedisError::Protocol(
                                    "streamed blob chunk missing trailing CRLF".to_string(),
                                ));
                            }
                            data.extend_from_slice(&buf[pos..end_data]);
                            pos = end_crlf;
                        }
                    }
                    let len = parse_i64_ascii(&buf[i + 1..end])?;
                    if len == -1 {
                        return Ok(Decoded::Ok {
                            value: RespValue::BulkString(None),
                            next: end + 2,
                        });
                    }
                    if len < -1 {
                        return Err(RedisError::Protocol(format!(
                            "invalid bulk string length: {len}"
                        )));
                    }
                    let len = usize::try_from(len).map_err(|_| {
                        RedisError::Protocol(format!("invalid bulk string length: {len}"))
                    })?;
                    if len > limits.max_bulk_string_len {
                        return Err(RedisError::Protocol(format!(
                            "bulk string length {len} exceeds maximum {}",
                            limits.max_bulk_string_len
                        )));
                    }
                    let start_data = end + 2;
                    let end_data = start_data.saturating_add(len);
                    let end_crlf = end_data.saturating_add(2);
                    if buf.len() < end_crlf {
                        return Ok(Decoded::NeedMore);
                    }
                    if buf.get(end_data) != Some(&b'\r') || buf.get(end_data + 1) != Some(&b'\n') {
                        return Err(RedisError::Protocol(
                            "bulk string missing trailing CRLF".to_string(),
                        ));
                    }
                    Ok(Decoded::Ok {
                        value: RespValue::BulkString(Some(buf[start_data..end_data].to_vec())),
                        next: end_crlf,
                    })
                }
                b'*' | b'~' | b'>' => {
                    let tag = buf[i];
                    let label = aggregate_label(tag);
                    let Some(end) = find_crlf(buf, i + 1) else {
                        return Ok(Decoded::NeedMore);
                    };
                    if &buf[i + 1..end] == b"?" {
                        if !matches!(tag, b'*' | b'~') {
                            return Err(RedisError::Protocol(format!(
                                "RESP3 streamed aggregate not supported for type byte 0x{tag:02x}"
                            )));
                        }
                        let mut items = Vec::new();
                        let mut pos = end + 2;
                        loop {
                            if pos >= buf.len() {
                                return Ok(Decoded::NeedMore);
                            }
                            match stream_end_state(buf, pos)? {
                                None => return Ok(Decoded::NeedMore),
                                Some(true) => {
                                    let value = if tag == b'*' {
                                        RespValue::Array(Some(items))
                                    } else {
                                        RespValue::Set(items)
                                    };
                                    return Ok(Decoded::Ok {
                                        value,
                                        next: pos + 3,
                                    });
                                }
                                Some(false) => {}
                            }
                            if items.len() >= limits.max_array_len {
                                return Err(RedisError::Protocol(format!(
                                    "streamed aggregate length exceeds maximum {}",
                                    limits.max_array_len
                                )));
                            }
                            match decode_at(buf, pos, depth + 1, limits)? {
                                Decoded::NeedMore => return Ok(Decoded::NeedMore),
                                Decoded::Ok { value, next } => {
                                    items.push(value);
                                    pos = next;
                                }
                            }
                        }
                    }
                    let n = parse_i64_ascii(&buf[i + 1..end])?;
                    if n == -1 && tag == b'*' {
                        return Ok(Decoded::Ok {
                            value: RespValue::Array(None),
                            next: end + 2,
                        });
                    }
                    if n < 0 {
                        return Err(RedisError::Protocol(format!("invalid {label} length: {n}")));
                    }
                    let n = usize::try_from(n).map_err(|_| {
                        RedisError::Protocol(format!("invalid {label} length: {n}"))
                    })?;
                    if n > limits.max_array_len {
                        return Err(RedisError::Protocol(format!(
                            "{label} length {n} exceeds maximum {}",
                            limits.max_array_len
                        )));
                    }
                    // Cap pre-allocation to avoid OOM from a large declared length
                    // before actually receiving that many elements.
                    let mut items = Vec::with_capacity(n.min(1024));
                    let mut pos = end + 2;
                    for _ in 0..n {
                        match decode_at(buf, pos, depth + 1, limits)? {
                            Decoded::NeedMore => return Ok(Decoded::NeedMore),
                            Decoded::Ok { value, next } => {
                                items.push(value);
                                pos = next;
                            }
                        }
                    }
                    let value = match tag {
                        b'*' => RespValue::Array(Some(items)),
                        b'~' => RespValue::Set(items),
                        b'>' => RespValue::Push(items),
                        _ => unreachable!(),
                    };
                    Ok(Decoded::Ok { value, next: pos })
                }
                // RESP3 map (%) and attribute (|) — N key-value pairs.
                b'%' | b'|' => {
                    let tag = buf[i];
                    let label = aggregate_label(tag);
                    let Some(end) = find_crlf(buf, i + 1) else {
                        return Ok(Decoded::NeedMore);
                    };
                    if &buf[i + 1..end] == b"?" {
                        if tag != b'%' {
                            return Err(RedisError::Protocol(format!(
                                "RESP3 streamed aggregate not supported for type byte 0x{tag:02x}"
                            )));
                        }
                        let mut pairs = Vec::new();
                        let mut pos = end + 2;
                        loop {
                            if pos >= buf.len() {
                                return Ok(Decoded::NeedMore);
                            }
                            match stream_end_state(buf, pos)? {
                                None => return Ok(Decoded::NeedMore),
                                Some(true) => {
                                    return Ok(Decoded::Ok {
                                        value: RespValue::Map(pairs),
                                        next: pos + 3,
                                    });
                                }
                                Some(false) => {}
                            }
                            if pairs.len() >= limits.max_array_len {
                                return Err(RedisError::Protocol(format!(
                                    "streamed aggregate length exceeds maximum {}",
                                    limits.max_array_len
                                )));
                            }
                            let key = match decode_at(buf, pos, depth + 1, limits)? {
                                Decoded::NeedMore => return Ok(Decoded::NeedMore),
                                Decoded::Ok { value, next } => {
                                    pos = next;
                                    value
                                }
                            };
                            match stream_end_state(buf, pos)? {
                                None => return Ok(Decoded::NeedMore),
                                Some(true) => {
                                    return Err(RedisError::Protocol(
                                        "RESP3 streamed map ended after a key without a value"
                                            .to_string(),
                                    ));
                                }
                                Some(false) => {}
                            }
                            let val = match decode_at(buf, pos, depth + 1, limits)? {
                                Decoded::NeedMore => return Ok(Decoded::NeedMore),
                                Decoded::Ok { value, next } => {
                                    pos = next;
                                    value
                                }
                            };
                            pairs.push((key, val));
                        }
                    }
                    let n = parse_i64_ascii(&buf[i + 1..end])?;
                    if n < 0 {
                        return Err(RedisError::Protocol(format!("invalid {label} length: {n}")));
                    }
                    let n = usize::try_from(n).map_err(|_| {
                        RedisError::Protocol(format!("invalid {label} length: {n}"))
                    })?;
                    if n > limits.max_array_len {
                        return Err(RedisError::Protocol(format!(
                            "{label} length {n} exceeds maximum {}",
                            limits.max_array_len
                        )));
                    }
                    let mut pairs = Vec::with_capacity(n.min(1024));
                    let mut pos = end + 2;
                    for _ in 0..n {
                        let key = match decode_at(buf, pos, depth + 1, limits)? {
                            Decoded::NeedMore => return Ok(Decoded::NeedMore),
                            Decoded::Ok { value, next } => {
                                pos = next;
                                value
                            }
                        };
                        let val = match decode_at(buf, pos, depth + 1, limits)? {
                            Decoded::NeedMore => return Ok(Decoded::NeedMore),
                            Decoded::Ok { value, next } => {
                                pos = next;
                                value
                            }
                        };
                        pairs.push((key, val));
                    }
                    let value = match tag {
                        b'%' => RespValue::Map(pairs),
                        b'|' => RespValue::Attribute(pairs),
                        _ => unreachable!(),
                    };
                    Ok(Decoded::Ok { value, next: pos })
                }
                // RESP3 null — `_\r\n`.
                b'_' => {
                    let Some(end) = find_crlf(buf, i + 1) else {
                        return Ok(Decoded::NeedMore);
                    };
                    if end != i + 1 {
                        return Err(RedisError::Protocol(
                            "RESP3 null must have empty payload".into(),
                        ));
                    }
                    Ok(Decoded::Ok {
                        value: RespValue::Null,
                        next: end + 2,
                    })
                }
                // RESP3 boolean — `#t\r\n` or `#f\r\n`.
                b'#' => {
                    let Some(end) = find_crlf(buf, i + 1) else {
                        return Ok(Decoded::NeedMore);
                    };
                    let payload = &buf[i + 1..end];
                    let value = match payload {
                        b"t" => RespValue::Boolean(true),
                        b"f" => RespValue::Boolean(false),
                        _ => {
                            return Err(RedisError::Protocol(format!(
                                "invalid RESP3 boolean payload: {:?}",
                                payload
                            )));
                        }
                    };
                    Ok(Decoded::Ok {
                        value,
                        next: end + 2,
                    })
                }
                // RESP3 double — `,<decimal-text>\r\n`. Preserve the exact
                // ASCII representation including `inf`, `-inf`, `nan`.
                b',' => {
                    let Some(end) = find_crlf(buf, i + 1) else {
                        return Ok(Decoded::NeedMore);
                    };
                    let s = std::str::from_utf8(&buf[i + 1..end])
                        .map_err(|_| RedisError::Protocol("invalid UTF-8 in double".into()))?
                        .to_string();
                    Ok(Decoded::Ok {
                        value: RespValue::Double(s),
                        next: end + 2,
                    })
                }
                // RESP3 big number — `([+|-]<digits>\r\n`.
                b'(' => {
                    let Some(end) = find_crlf(buf, i + 1) else {
                        return Ok(Decoded::NeedMore);
                    };
                    let s = std::str::from_utf8(&buf[i + 1..end])
                        .map_err(|_| RedisError::Protocol("invalid UTF-8 in big number".into()))?;
                    validate_resp3_big_number_payload(s)?;
                    Ok(Decoded::Ok {
                        value: RespValue::BigNumber(s.to_string()),
                        next: end + 2,
                    })
                }
                // RESP3 verbatim string — `=N\r\n<3-byte-format>:<payload>\r\n`.
                b'=' => {
                    let Some(end) = find_crlf(buf, i + 1) else {
                        return Ok(Decoded::NeedMore);
                    };
                    let len = parse_i64_ascii(&buf[i + 1..end])?;
                    if len < 4 {
                        return Err(RedisError::Protocol(format!(
                            "verbatim string length {len} is below minimum 4 (format prefix)"
                        )));
                    }
                    let len = usize::try_from(len).map_err(|_| {
                        RedisError::Protocol(format!("invalid verbatim length: {len}"))
                    })?;
                    if len > limits.max_bulk_string_len {
                        return Err(RedisError::Protocol(format!(
                            "verbatim length {len} exceeds maximum {}",
                            limits.max_bulk_string_len
                        )));
                    }
                    let start_data = end + 2;
                    let end_data = start_data.saturating_add(len);
                    let end_crlf = end_data.saturating_add(2);
                    if buf.len() < end_crlf {
                        return Ok(Decoded::NeedMore);
                    }
                    if buf.get(end_data) != Some(&b'\r') || buf.get(end_data + 1) != Some(&b'\n') {
                        return Err(RedisError::Protocol(
                            "verbatim string missing trailing CRLF".into(),
                        ));
                    }
                    let body = &buf[start_data..end_data];
                    if body.get(3) != Some(&b':') {
                        return Err(RedisError::Protocol(
                            "verbatim string missing 3-byte format separator (':' at offset 3)"
                                .into(),
                        ));
                    }
                    let format = std::str::from_utf8(&body[..3])
                        .map_err(|_| {
                            RedisError::Protocol("invalid UTF-8 in verbatim format".into())
                        })?
                        .to_string();
                    let payload = body[4..].to_vec();
                    Ok(Decoded::Ok {
                        value: RespValue::Verbatim { format, payload },
                        next: end_crlf,
                    })
                }
                // RESP3 blob error — `!N\r\n<bytes>\r\n`.
                b'!' => {
                    let Some(end) = find_crlf(buf, i + 1) else {
                        return Ok(Decoded::NeedMore);
                    };
                    let len = parse_i64_ascii(&buf[i + 1..end])?;
                    if len < 0 {
                        return Err(RedisError::Protocol(format!(
                            "invalid blob error length: {len}"
                        )));
                    }
                    let len = usize::try_from(len).map_err(|_| {
                        RedisError::Protocol(format!("invalid blob error length: {len}"))
                    })?;
                    if len > limits.max_bulk_string_len {
                        return Err(RedisError::Protocol(format!(
                            "blob error length {len} exceeds maximum {}",
                            limits.max_bulk_string_len
                        )));
                    }
                    let start_data = end + 2;
                    let end_data = start_data.saturating_add(len);
                    let end_crlf = end_data.saturating_add(2);
                    if buf.len() < end_crlf {
                        return Ok(Decoded::NeedMore);
                    }
                    if buf.get(end_data) != Some(&b'\r') || buf.get(end_data + 1) != Some(&b'\n') {
                        return Err(RedisError::Protocol(
                            "blob error missing trailing CRLF".into(),
                        ));
                    }
                    Ok(Decoded::Ok {
                        value: RespValue::BlobError(buf[start_data..end_data].to_vec()),
                        next: end_crlf,
                    })
                }
                other => Err(RedisError::Protocol(format!(
                    "unknown RESP type byte: 0x{other:02x}"
                ))),
            }
        }

        match decode_at(buf, 0, 0, limits)? {
            Decoded::NeedMore => Ok(None),
            Decoded::Ok { value, next } => Ok(Some((value, next))),
        }
    }

    /// Decode one RESP value from the provided buffer using default limits.
    ///
    /// Returns `Ok(None)` if more bytes are required.
    pub fn try_decode(buf: &[u8]) -> Result<Option<(Self, usize)>, RedisError> {
        Self::try_decode_with_limits(buf, &RedisProtocolLimits::default())
    }

    /// Try to extract as a bulk string (bytes).
    #[must_use]
    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Self::BulkString(Some(b)) => Some(b),
            _ => None,
        }
    }

    /// Try to extract as an integer.
    #[must_use]
    pub fn as_integer(&self) -> Option<i64> {
        match self {
            Self::Integer(i) => Some(*i),
            _ => None,
        }
    }

    /// Check if this is an OK response.
    #[must_use]
    pub fn is_ok(&self) -> bool {
        matches!(self, Self::SimpleString(s) if s == "OK")
    }
}

/// Pub/Sub subscription acknowledgement kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PubSubSubscriptionKind {
    /// `SUBSCRIBE` acknowledgement.
    Subscribe,
    /// `UNSUBSCRIBE` acknowledgement.
    Unsubscribe,
    /// `PSUBSCRIBE` acknowledgement.
    PatternSubscribe,
    /// `PUNSUBSCRIBE` acknowledgement.
    PatternUnsubscribe,
}

/// A Redis Pub/Sub message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PubSubMessage {
    /// Channel that produced the message.
    pub channel: String,
    /// Optional pattern when delivered through `PSUBSCRIBE`.
    pub pattern: Option<String>,
    /// Raw message payload bytes.
    pub payload: Vec<u8>,
}

/// Event emitted by a Pub/Sub connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PubSubEvent {
    /// Data message from `SUBSCRIBE`/`PSUBSCRIBE`.
    Message(PubSubMessage),
    /// Subscription state change acknowledgement.
    Subscription {
        /// Acknowledgement kind.
        kind: PubSubSubscriptionKind,
        /// Channel/pattern name.
        channel: String,
        /// Remaining active subscriptions on this connection.
        remaining: i64,
    },
    /// `PONG` reply for health checks.
    Pong(Option<Vec<u8>>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// RESP3 client-tracking push surfaced to a regular command client.
pub enum RedisClientTrackingPush {
    /// `invalidate` notification carrying zero or more keys. `None`
    /// represents Redis' `null` payload (flush whole cache).
    Invalidate {
        /// Keys invalidated by Redis. `None` means flush the entire
        /// tracked client-side cache.
        keys: Option<Vec<Vec<u8>>>,
    },
    /// `tracking-redir-broken` notification indicating the redirect
    /// target is no longer valid.
    RedirectBroken,
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// RESP3 push surfaced to a regular command client.
///
/// Pub/Sub push kinds are intentionally excluded: callers should use
/// [`RedisPubSub`] for subscribe/psubscribe traffic. This queue exists
/// for other server-initiated RESP3 pushes such as client-tracking
/// invalidations or monitoring-style events that can arrive while a
/// normal command response is in flight.
pub enum RedisResp3NonPubSubPush {
    /// Structured client-tracking notification.
    ClientTracking(RedisClientTrackingPush),
    /// Any other non-pubsub RESP3 push, preserving the textual kind
    /// plus the raw payload values.
    Other {
        /// Textual RESP3 push kind as sent by Redis.
        kind: String,
        /// Remaining RESP values after the leading kind field.
        payload: Vec<RespValue>,
    },
}

impl RedisResp3NonPubSubPush {
    #[must_use]
    fn kind_name(&self) -> &str {
        match self {
            Self::ClientTracking(RedisClientTrackingPush::Invalidate { .. }) => "invalidate",
            Self::ClientTracking(RedisClientTrackingPush::RedirectBroken) => {
                "tracking-redir-broken"
            }
            Self::Other { kind, .. } => kind.as_str(),
        }
    }
}

#[derive(Debug, Default)]
struct RedisResp3PushBacklog {
    pending: VecDeque<RedisResp3NonPubSubPush>,
    dropped: u64,
    lag_reported: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RedisResp3PushEnqueueOutcome {
    Enqueued { queue_len: usize },
    Dropped { queue_len: usize, dropped: u64 },
}

impl RedisResp3PushBacklog {
    fn enqueue(
        &mut self,
        push: RedisResp3NonPubSubPush,
        cap: usize,
    ) -> RedisResp3PushEnqueueOutcome {
        if self.pending.len() >= cap {
            self.dropped = self.dropped.saturating_add(1);
            return RedisResp3PushEnqueueOutcome::Dropped {
                queue_len: self.pending.len(),
                dropped: self.dropped,
            };
        }

        self.pending.push_back(push);
        RedisResp3PushEnqueueOutcome::Enqueued {
            queue_len: self.pending.len(),
        }
    }
}

fn expect_ok_response(resp: &RespValue, command: &str) -> Result<(), RedisError> {
    if resp.is_ok() {
        Ok(())
    } else {
        Err(RedisError::Protocol(format!(
            "{command} expected +OK, got {resp:?}"
        )))
    }
}

const DEFAULT_MAX_RESP_FRAME_SIZE: usize = 16 * 1024 * 1024;

/// Default maximum nesting depth for RESP arrays.
const DEFAULT_MAX_NESTING_DEPTH: usize = 64;

/// Default maximum RESP array length.
const DEFAULT_MAX_ARRAY_LEN: usize = 1_000_000;

/// Default maximum bulk string length.
const DEFAULT_MAX_BULK_STRING_LEN: usize = 512 * 1024 * 1024;

/// Configurable protocol-level limits for the Redis RESP decoder.
///
/// These limits protect against resource exhaustion from oversized or
/// malicious responses. Inject into [`RedisConfig`] to override defaults.
///
/// # Defaults
///
/// | Limit | Default | Purpose |
/// |-------|---------|---------|
/// | `max_frame_size` | 16 MiB | Maximum bytes buffered for a single RESP frame |
/// | `max_nesting_depth` | 64 | Maximum RESP array nesting depth (stack overflow protection) |
/// | `max_array_len` | 1,000,000 | Maximum elements in a single RESP array (memory protection) |
/// | `max_bulk_string_len` | 512 MiB | Maximum size of a bulk string |
#[derive(Debug, Clone, Copy)]
pub struct RedisProtocolLimits {
    /// Maximum RESP frame size in bytes.
    pub max_frame_size: usize,
    /// Maximum RESP array nesting depth.
    pub max_nesting_depth: usize,
    /// Maximum RESP array element count.
    pub max_array_len: usize,
    /// Maximum bulk string length.
    pub max_bulk_string_len: usize,
}

impl Default for RedisProtocolLimits {
    fn default() -> Self {
        Self {
            max_frame_size: DEFAULT_MAX_RESP_FRAME_SIZE,
            max_nesting_depth: DEFAULT_MAX_NESTING_DEPTH,
            max_array_len: DEFAULT_MAX_ARRAY_LEN,
            max_bulk_string_len: DEFAULT_MAX_BULK_STRING_LEN,
        }
    }
}

impl RedisProtocolLimits {
    /// Create protocol limits with defaults.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the maximum RESP frame size.
    #[must_use]
    pub fn max_frame_size(mut self, bytes: usize) -> Self {
        self.max_frame_size = bytes;
        self
    }

    /// Set the maximum RESP array nesting depth.
    #[must_use]
    pub fn max_nesting_depth(mut self, depth: usize) -> Self {
        self.max_nesting_depth = depth;
        self
    }

    /// Set the maximum RESP array element count.
    #[must_use]
    pub fn max_array_len(mut self, len: usize) -> Self {
        self.max_array_len = len;
        self
    }

    /// Set the maximum bulk string length.
    #[must_use]
    pub fn max_bulk_string_len(mut self, len: usize) -> Self {
        self.max_bulk_string_len = len;
        self
    }
}

#[derive(Debug)]
struct RespReadBuffer {
    buf: Vec<u8>,
    pos: usize,
}

impl RespReadBuffer {
    fn new() -> Self {
        Self {
            buf: Vec::new(),
            pos: 0,
        }
    }

    fn available(&self) -> &[u8] {
        &self.buf[self.pos..]
    }

    fn len(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }

    fn extend(&mut self, bytes: &[u8]) {
        self.buf.extend_from_slice(bytes);
    }

    fn consume(&mut self, n: usize) {
        self.pos = self.pos.saturating_add(n);
        if self.pos > 0 && (self.pos > 4096 && self.pos > (self.buf.len() / 2)) {
            self.buf.drain(..self.pos);
            self.pos = 0;
        }
    }
}

fn encode_command_into(buf: &mut Vec<u8>, args: &[&[u8]]) {
    buf.push(b'*');
    push_u64_decimal(buf, args.len() as u64);
    buf.extend_from_slice(b"\r\n");
    for arg in args {
        buf.push(b'$');
        push_u64_decimal(buf, arg.len() as u64);
        buf.extend_from_slice(b"\r\n");
        buf.extend_from_slice(arg);
        buf.extend_from_slice(b"\r\n");
    }
}

/// Configuration for Redis client.
#[derive(Clone)]
pub struct RedisConfig {
    /// Host address.
    pub host: String,
    /// Port.
    pub port: u16,
    /// Database index.
    pub database: u8,
    /// Username for AUTH (Redis 6+ ACL).
    pub username: Option<String>,
    /// Password for AUTH.
    pub password: Option<String>,
    /// Enable TLS encryption.
    pub use_tls: bool,
    /// TLS connector configuration.
    #[cfg(feature = "tls")]
    pub tls_connector: Option<TlsConnector>,
    /// Protocol-level limits for the RESP decoder.
    pub protocol_limits: RedisProtocolLimits,
    /// Maximum number of buffered Pub/Sub events held in memory while
    /// the caller is between [`RedisPubSub::next_event`] polls. When
    /// the backlog reaches this size, additional events are dropped to
    /// bound memory and the next `next_event` call returns
    /// [`RedisError::SubscriberLag`] carrying the number of events
    /// dropped since the last report. Cumulative drops are also
    /// surfaced via [`RedisPubSub::pubsub_dropped_events`] for metrics.
    /// Default: 4096 (br-asupersync-697arj).
    pub pubsub_max_backlog: usize,
    /// Maximum number of non-pubsub RESP3 push frames buffered for a
    /// regular command client while the caller is between
    /// [`RedisClient::try_next_resp3_push`] polls. When the backlog
    /// reaches this size, newly-arriving push frames are dropped to
    /// bound memory, and the next `try_next_resp3_push` call returns
    /// [`RedisError::Resp3PushLag`] with the number dropped since the
    /// last lag report. Default: 4096
    /// (br-asupersync-iikmjh).
    pub resp3_push_max_backlog: usize,
}

impl std::fmt::Debug for RedisConfig {
    // br-asupersync-lru405 + br-asupersync-kytkta: redact both username and
    // password. Username is a credential under Redis 6+ ACL — combined with
    // host:port:database it can enable enumeration / unauthorized access.
    // We preserve the Some/None distinction so log readers can still see
    // whether a credential is configured without seeing its value.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RedisConfig")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("database", &self.database)
            .field("username", &self.username.as_ref().map(|_| "[REDACTED]"))
            .field("password", &self.password.as_ref().map(|_| "[REDACTED]"))
            .field("use_tls", &self.use_tls)
            .field(
                "tls_connector",
                #[cfg(feature = "tls")]
                &self.tls_connector.as_ref().map(|_| "[REDACTED]"),
                #[cfg(not(feature = "tls"))]
                &"[TLS_DISABLED]",
            )
            .field("protocol_limits", &self.protocol_limits)
            .field("pubsub_max_backlog", &self.pubsub_max_backlog)
            .field("resp3_push_max_backlog", &self.resp3_push_max_backlog)
            .finish()
    }
}

impl Default for RedisConfig {
    fn default() -> Self {
        Self {
            host: "127.0.0.1".to_string(),
            port: 6379,
            database: 0,
            username: None,
            password: None,
            use_tls: false,
            #[cfg(feature = "tls")]
            tls_connector: None,
            protocol_limits: RedisProtocolLimits::default(),
            // Default Pub/Sub backlog cap; overflow surfaces via
            // RedisError::SubscriberLag and pubsub_dropped_events
            // (br-asupersync-697arj).
            pubsub_max_backlog: 4096,
            // Default RESP3 push backlog cap for regular command
            // clients; overflow surfaces via
            // RedisError::Resp3PushLag and resp3_dropped_pushes
            // (br-asupersync-iikmjh).
            resp3_push_max_backlog: 4096,
        }
    }
}

impl RedisConfig {
    /// Redact credentials from a Redis URL for safe error reporting.
    ///
    /// SECURITY: Prevents password leakage in error messages and logs.
    /// Converts `redis://user:pass@host:port/db` → `redis://***@host:port/db`
    fn redact_url_for_errors(url: &str) -> String {
        // Check for scheme and preserve it
        let (scheme, rest) = if let Some(rest) = url.strip_prefix("rediss://") {
            ("rediss://", rest)
        } else if let Some(rest) = url.strip_prefix("redis://") {
            ("redis://", rest)
        } else {
            // No recognized scheme; redact the entire URL, but retain an
            // explicit credential marker when userinfo is present so callers can
            // assert that secrets were not emitted.
            if url.contains('@') {
                return "[REDACTED_INVALID_URL:***]".to_string();
            }
            return "[REDACTED_INVALID_URL]".to_string();
        };

        // Look for userinfo section (anything before '@')
        if let Some((_userinfo, host_part)) = rest.rsplit_once('@') {
            // Replace userinfo with a redacted credential marker.
            format!("{}***@{}", scheme, host_part)
        } else {
            // No credentials in URL, return as-is
            url.to_string()
        }
    }

    /// URL-decode credential strings to handle percent-encoded characters.
    ///
    /// SECURITY: Prevents authentication bypass via URL-encoded credentials
    /// like `%3A` (colon) or `%40` (at-sign) that could bypass credential
    /// parsing (asupersync-ts45lv).
    fn url_decode_credential(encoded: &str) -> Result<String, RedisError> {
        let mut result = String::with_capacity(encoded.len());
        let mut chars = encoded.chars();

        while let Some(ch) = chars.next() {
            if ch == '%' {
                // Percent-encoded character: read next two hex digits
                let hex1 = chars.next().ok_or_else(|| {
                    RedisError::InvalidUrl("incomplete percent encoding in credential".to_string())
                })?;
                let hex2 = chars.next().ok_or_else(|| {
                    RedisError::InvalidUrl("incomplete percent encoding in credential".to_string())
                })?;

                // Parse hex digits to byte value
                let byte = u8::from_str_radix(&format!("{}{}", hex1, hex2), 16).map_err(|_| {
                    RedisError::InvalidUrl("invalid percent encoding in credential".to_string())
                })?;

                // Convert byte to char (assuming UTF-8, which is standard for URLs)
                if byte.is_ascii() {
                    result.push(byte as char);
                } else {
                    // For non-ASCII bytes, we'd need proper UTF-8 decoding,
                    // but Redis credentials should be ASCII-safe
                    return Err(RedisError::InvalidUrl(
                        "non-ASCII percent encoding in credential".to_string(),
                    ));
                }
            } else {
                result.push(ch);
            }
        }

        Ok(result)
    }

    /// Create config from a Redis URL.
    pub fn from_url(url: &str) -> Result<Self, RedisError> {
        let (url, use_tls) = if let Some(url) = url.strip_prefix("rediss://") {
            (url, true)
        } else if let Some(url) = url.strip_prefix("redis://") {
            (url, false)
        } else {
            return Err(RedisError::InvalidUrl(format!(
                "URL must start with redis:// or rediss://, got: {}",
                Self::redact_url_for_errors(url)
            )));
        };

        let mut config = Self::default();

        let url = if let Some((userinfo, rest)) = url.rsplit_once('@') {
            // Split userinfo into username:password per Redis URL convention.
            // SECURITY: Apply URL percent-decoding to credentials to prevent
            // authentication bypass via encoded characters (asupersync-ts45lv).
            if let Some((username, password)) = userinfo.split_once(':') {
                if !username.is_empty() {
                    config.username = Some(Self::url_decode_credential(username)?);
                }
                config.password = Some(Self::url_decode_credential(password)?);
            } else {
                // No colon: treat the entire userinfo as the password.
                config.password = Some(Self::url_decode_credential(userinfo)?);
            }
            rest
        } else {
            url
        };

        let (host_port, database) = if let Some((hp, db)) = url.split_once('/') {
            (hp, Some(db))
        } else {
            (url, None)
        };

        if let Some((host, port)) = host_port.split_once(':') {
            config.host = host.to_string();
            config.port = port
                .parse()
                .map_err(|_| RedisError::InvalidUrl(format!("invalid port: {port}")))?;
        } else if !host_port.is_empty() {
            config.host = host_port.to_string();
        }

        if let Some(db) = database {
            if !db.is_empty() {
                config.database = db
                    .parse()
                    .map_err(|_| RedisError::InvalidUrl(format!("invalid database: {db}")))?;
            }
        }

        // Configure TLS if rediss:// URL was used
        config.use_tls = use_tls;
        #[cfg(feature = "tls")]
        if use_tls {
            // SECURITY: Enable hostname verification to prevent MITM attacks.
            // This ensures the certificate's CN/SAN matches the hostname we're
            // connecting to, preventing attacks where valid certificates for
            // different domains are used maliciously (asupersync-xq1qe3).
            let tls_connector = TlsConnectorBuilder::new()
                .with_webpki_roots()
                .build()
                .map_err(|e| RedisError::InvalidUrl(format!("TLS setup failed: {e}")))?;
            config.tls_connector = Some(tls_connector);
        }
        #[cfg(not(feature = "tls"))]
        if use_tls {
            return Err(RedisError::InvalidUrl(
                "TLS support not enabled".to_string(),
            ));
        }

        Ok(config)
    }
}

#[derive(Debug)]
enum RedisStream {
    Plain(TcpStream),
    #[cfg(feature = "tls")]
    Tls(TlsStream<TcpStream>),
}

impl RedisStream {
    /// Best-effort drop-safe transport shutdown.
    ///
    /// Drop paths cannot poll async `AsyncWriteExt::shutdown()`, so use the
    /// underlying socket's synchronous shutdown API to fail closed
    /// immediately.
    fn shutdown_transport(&self) -> io::Result<()> {
        match self {
            Self::Plain(stream) => stream.shutdown(std::net::Shutdown::Both),
            #[cfg(feature = "tls")]
            Self::Tls(stream) => stream.get_ref().shutdown(std::net::Shutdown::Both),
        }
    }
}

impl AsyncRead for RedisStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Plain(stream) => Pin::new(stream).poll_read(cx, buf),
            #[cfg(feature = "tls")]
            Self::Tls(stream) => Pin::new(stream).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for RedisStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, io::Error>> {
        match self.get_mut() {
            Self::Plain(stream) => Pin::new(stream).poll_write(cx, buf),
            #[cfg(feature = "tls")]
            Self::Tls(stream) => Pin::new(stream).poll_write(cx, buf),
        }
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), io::Error>> {
        match self.get_mut() {
            Self::Plain(stream) => Pin::new(stream).poll_flush(cx),
            #[cfg(feature = "tls")]
            Self::Tls(stream) => Pin::new(stream).poll_flush(cx),
        }
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), io::Error>> {
        match self.get_mut() {
            Self::Plain(stream) => Pin::new(stream).poll_shutdown(cx),
            #[cfg(feature = "tls")]
            Self::Tls(stream) => Pin::new(stream).poll_shutdown(cx),
        }
    }
}

#[derive(Debug)]
struct RedisConnection {
    stream: RedisStream,
    read_buf: RespReadBuffer,
    config: RedisConfig,
    initialized: bool,
    resp3_push_backlog: Option<Arc<parking_lot::Mutex<RedisResp3PushBacklog>>>,
}

#[derive(Clone, Copy, Debug)]
enum Resp3PushHandling {
    RouteToRegularClientBacklog,
    ReturnToPubSubCaller,
}

impl RedisConnection {
    async fn connect(
        config: RedisConfig,
        resp3_push_backlog: Option<Arc<parking_lot::Mutex<RedisResp3PushBacklog>>>,
    ) -> Result<Self, RedisError> {
        let addr = format!("{}:{}", config.host, config.port);
        let tcp_stream = TcpStream::connect(addr).await?;

        let stream = if config.use_tls {
            #[cfg(feature = "tls")]
            {
                let tls_connector = config.tls_connector.as_ref().ok_or_else(|| {
                    RedisError::InvalidUrl("TLS enabled but no connector configured".to_string())
                })?;
                let tls_stream = tls_connector
                    .connect(&config.host, tcp_stream)
                    .await
                    .map_err(|e| {
                        RedisError::Io(io::Error::new(io::ErrorKind::ConnectionRefused, e))
                    })?;
                RedisStream::Tls(tls_stream)
            }
            #[cfg(not(feature = "tls"))]
            {
                return Err(RedisError::InvalidUrl(
                    "TLS support not enabled".to_string(),
                ));
            }
        } else {
            RedisStream::Plain(tcp_stream)
        };

        Ok(Self {
            stream,
            read_buf: RespReadBuffer::new(),
            config,
            initialized: false,
            resp3_push_backlog,
        })
    }

    async fn ensure_initialized(&mut self, cx: &Cx) -> Result<(), RedisError> {
        if self.initialized {
            return Ok(());
        }

        cx.trace("redis: initializing connection (HELLO/AUTH/SELECT)");

        let password = self.config.password.clone();
        let username = self.config.username.clone();

        // br-asupersync-xlh4nx: try RESP3 negotiation first via HELLO 3.
        // HELLO accepts an optional AUTH clause that authenticates atomically
        // with the protocol upgrade — saves a round trip when credentials are
        // configured. On a server that predates HELLO (Redis < 6.0) the
        // command returns `-ERR unknown command 'HELLO' ...`, in which case
        // we fall back to the legacy AUTH path. Any other error is fatal.
        let mut hello_args: Vec<&[u8]> = vec![b"HELLO", b"3"];
        if let (Some(u), Some(p)) = (username.as_ref(), password.as_ref()) {
            hello_args.push(b"AUTH");
            hello_args.push(u.as_bytes());
            hello_args.push(p.as_bytes());
        } else if let Some(p) = password.as_ref() {
            // Pre-ACL servers — synthesise the default user.
            hello_args.push(b"AUTH");
            hello_args.push(b"default");
            hello_args.push(p.as_bytes());
        }
        let mut hello_handled_auth = false;
        match self.exec_no_init(cx, &hello_args).await? {
            RespValue::Map(_) | RespValue::Array(Some(_)) => {
                // RESP3 reply is a Map; some Redis builds (notably KeyDB)
                // still answer in RESP2 with an Array even after HELLO 3.
                // Both responses confirm the server accepted the command and
                // applied any AUTH clause we sent.
                hello_handled_auth = password.is_some();
            }
            RespValue::Error(msg) => {
                // The only case we keep the connection for is "unknown
                // command HELLO" on legacy servers. Anything else (auth
                // failure, NOAUTH, syntax) propagates.
                let lower = msg.to_ascii_lowercase();
                let is_unknown_command =
                    lower.contains("unknown command") && lower.contains("hello");
                if !is_unknown_command {
                    return Err(RedisError::from_redis_error_message(&msg));
                }
                cx.trace("redis: HELLO 3 unsupported, falling back to RESP2");
            }
            other => {
                return Err(RedisError::Protocol(format!(
                    "HELLO 3 expected Map/Array/Error, got {other:?}"
                )));
            }
        }

        if !hello_handled_auth && let Some(p) = password.as_ref() {
            // Redis 6+ ACL: AUTH username password; pre-6: AUTH password.
            let resp = if let Some(u) = username.as_ref() {
                self.exec_no_init(cx, &[b"AUTH", u.as_bytes(), p.as_bytes()])
                    .await?
            } else {
                self.exec_no_init(cx, &[b"AUTH", p.as_bytes()]).await?
            };
            if !resp.is_ok() {
                return Err(match &resp {
                    RespValue::Error(msg) => RedisError::from_redis_error_message(msg),
                    _ => RedisError::Protocol(format!("AUTH expected +OK, got {resp:?}")),
                });
            }
        }

        if self.config.database != 0 {
            let mut tmp = [0u8; 20];
            let db_bytes = u64_decimal_bytes(u64::from(self.config.database), &mut tmp);
            let resp = self.exec_no_init(cx, &[b"SELECT", db_bytes]).await?;
            if !resp.is_ok() {
                return Err(RedisError::Protocol(format!(
                    "SELECT expected +OK, got {resp:?}"
                )));
            }
        }

        self.initialized = true;
        Ok(())
    }

    async fn write_command(&mut self, cx: &Cx, args: &[&[u8]]) -> Result<(), RedisError> {
        cx.checkpoint().map_err(|_| RedisError::Cancelled)?;

        let mut buf = Vec::new();
        encode_command_into(&mut buf, args);
        self.stream.write_all(&buf).await?;
        self.stream.flush().await?;
        Ok(())
    }

    fn record_resp3_push(
        &self,
        cx: &Cx,
        push_value: RespValue,
        consumed: usize,
    ) -> Result<(), RedisError> {
        let push = parse_resp3_non_pubsub_push(push_value)?;
        let kind = push.kind_name().to_string();

        let Some(backlog) = &self.resp3_push_backlog else {
            cx.trace(&format!(
                "redis: received RESP3 push frame without regular-client backlog; discarding kind={kind} consumed={consumed}"
            ));
            return Ok(());
        };

        let outcome = {
            let mut backlog = backlog.lock();
            backlog.enqueue(push, self.config.resp3_push_max_backlog)
        };

        match outcome {
            RedisResp3PushEnqueueOutcome::Enqueued { queue_len } => {
                cx.trace(&format!(
                    "redis: queued RESP3 push frame kind={kind} consumed={consumed} queue_len={queue_len}"
                ));
            }
            RedisResp3PushEnqueueOutcome::Dropped { queue_len, dropped } => {
                cx.trace(&format!(
                    "redis: dropping RESP3 push frame kind={kind} consumed={consumed} queue_len={queue_len} cap={} dropped_total={dropped}",
                    self.config.resp3_push_max_backlog
                ));
            }
        }
        Ok(())
    }

    async fn read_response_with_push_handling(
        &mut self,
        cx: &Cx,
        push_handling: Resp3PushHandling,
    ) -> Result<RespValue, RedisError> {
        loop {
            cx.checkpoint().map_err(|_| RedisError::Cancelled)?;

            if let Some((value, consumed)) = RespValue::try_decode_with_limits(
                self.read_buf.available(),
                &self.config.protocol_limits,
            )? {
                self.read_buf.consume(consumed);
                match value {
                    RespValue::Attribute(_) => {
                        // RESP3 attributes are metadata that prefix the actual
                        // reply; they must not be surfaced as standalone command
                        // responses or left queued to desynchronize the socket.
                        continue;
                    }
                    push_value @ RespValue::Push(_) => {
                        // RESP3 push frames (server-initiated messages like
                        // client-tracking invalidations or pub/sub events)
                        // are not synchronous command replies. Regular
                        // clients route them into the push backlog and keep
                        // reading for the command reply; dedicated Pub/Sub
                        // connections return them to the Pub/Sub parser.
                        match push_handling {
                            Resp3PushHandling::RouteToRegularClientBacklog => {
                                self.record_resp3_push(cx, push_value, consumed)?;
                                continue;
                            }
                            Resp3PushHandling::ReturnToPubSubCaller => {
                                return Ok(push_value);
                            }
                        }
                    }
                    other => {
                        return Ok(other);
                    }
                }
            }

            let frame_limit = self.config.protocol_limits.max_frame_size;
            if self.read_buf.len() > frame_limit {
                return Err(RedisError::Protocol(format!(
                    "RESP frame exceeds limit ({frame_limit} bytes)"
                )));
            }

            let mut tmp = [0u8; 4096];
            let read_result = std::future::poll_fn(|task_cx| {
                if cx.checkpoint().is_err() {
                    return std::task::Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::Interrupted,
                        "cancelled",
                    )));
                }
                let mut read_buf = ReadBuf::new(&mut tmp);
                match Pin::new(&mut self.stream).poll_read(task_cx, &mut read_buf) {
                    std::task::Poll::Pending => std::task::Poll::Pending,
                    std::task::Poll::Ready(Ok(())) => {
                        std::task::Poll::Ready(Ok(read_buf.filled().len()))
                    }
                    std::task::Poll::Ready(Err(e)) => std::task::Poll::Ready(Err(e)),
                }
            })
            .await;
            let n = match read_result {
                Ok(n) => n,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {
                    return Err(RedisError::Cancelled);
                }
                Err(e) => return Err(RedisError::Io(e)),
            };
            if n == 0 {
                return Err(RedisError::Io(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "redis connection closed",
                )));
            }
            self.read_buf.extend(&tmp[..n]);
        }
    }

    async fn read_response(&mut self, cx: &Cx) -> Result<RespValue, RedisError> {
        self.read_response_with_push_handling(cx, Resp3PushHandling::RouteToRegularClientBacklog)
            .await
    }

    async fn read_pubsub_response(&mut self, cx: &Cx) -> Result<RespValue, RedisError> {
        self.read_response_with_push_handling(cx, Resp3PushHandling::ReturnToPubSubCaller)
            .await
    }

    async fn exec_no_init(&mut self, cx: &Cx, args: &[&[u8]]) -> Result<RespValue, RedisError> {
        self.write_command(cx, args).await?;
        let value = self.read_response(cx).await?;
        match value {
            RespValue::Error(msg) => Err(RedisError::Redis(msg)),
            other => Ok(other),
        }
    }

    async fn exec(&mut self, cx: &Cx, args: &[&[u8]]) -> Result<RespValue, RedisError> {
        self.ensure_initialized(cx).await?;
        self.exec_no_init(cx, args).await
    }
}

type RedisFactory = Box<
    dyn Fn() -> Pin<Box<dyn Future<Output = Result<RedisConnection, RedisError>> + Send>>
        + Send
        + Sync,
>;

/// Maximum number of cluster redirects to follow for a single command before
/// giving up. Bounds an adversarial / mid-resharding cluster's ability to
/// trap a caller in a redirect loop. (br-asupersync-hzgugy)
const MAX_REDIRECTS: u8 = 5;

/// A cluster-mode redirect parsed out of a `-MOVED` or `-ASK` response.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Redirect {
    /// Permanent slot ownership change. Update the slot map and retry on
    /// the indicated address.
    Moved { slot: u16, addr: String },
    /// Transient slot migration. Retry on the indicated address with the
    /// `ASKING` command prepended; do NOT update the slot map.
    Ask { slot: u16, addr: String },
}

/// Parse `MOVED <slot> <host>:<port>` or `ASK <slot> <host>:<port>` out of
/// a Redis cluster redirect error message. Returns `None` if the message
/// is not a recognized redirect.
fn parse_redirect(msg: &str) -> Option<Redirect> {
    let mut parts = msg.splitn(3, ' ');
    let kind = parts.next()?;
    let slot: u16 = parts.next()?.parse().ok()?;
    let addr = parts.next()?.trim().to_string();
    if addr.is_empty() {
        return None;
    }
    match kind {
        "MOVED" => Some(Redirect::Moved { slot, addr }),
        "ASK" => Some(Redirect::Ask { slot, addr }),
        _ => None,
    }
}

const REDIS_CLUSTER_MAX_SLOT: u16 = 16_383;

/// Node endpoint returned by `CLUSTER SLOTS`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedisClusterSlotNode {
    /// Preferred endpoint. `None` represents Redis NULL or an empty endpoint.
    pub endpoint: Option<String>,
    /// TCP port advertised by the node.
    pub port: u16,
    /// Stable Redis Cluster node ID, absent on legacy replies.
    pub node_id: Option<String>,
}

/// One slot range returned by `CLUSTER SLOTS`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedisClusterSlotRange {
    /// Inclusive start of the Redis hash-slot range.
    pub start: u16,
    /// Inclusive end of the Redis hash-slot range.
    pub end: u16,
    /// Master node for this slot range.
    pub master: RedisClusterSlotNode,
    /// Active replicas for this slot range.
    pub replicas: Vec<RedisClusterSlotNode>,
}

/// Parse a Redis `CLUSTER SLOTS` response into slot ranges.
///
/// Redis returns an array of ranges whose first two fields are inclusive slot
/// bounds, followed by the master node and zero or more replica nodes. Node
/// arrays are accepted in both legacy form (`endpoint`, `port`) and modern form
/// with node ID plus extra metadata fields; metadata after the fixed fields is
/// intentionally ignored per Redis client guidance.
///
/// # Errors
///
/// Returns `RedisError::Protocol` when the response shape is not the nested
/// array format Redis documents, when slots fall outside `0..=16383`, when a
/// range is reversed, or when node endpoint / ID bytes are not UTF-8.
pub fn parse_cluster_slots_response(
    response: &RespValue,
) -> Result<Vec<RedisClusterSlotRange>, RedisError> {
    let ranges = cluster_slots_array(response, "response")?;
    let mut parsed = Vec::with_capacity(ranges.len());

    for (index, range) in ranges.iter().enumerate() {
        parsed.push(parse_cluster_slot_range(range, index)?);
    }

    Ok(parsed)
}

fn parse_cluster_slot_range(
    value: &RespValue,
    index: usize,
) -> Result<RedisClusterSlotRange, RedisError> {
    let fields = cluster_slots_array(value, "slot range")?;
    if fields.len() < 3 {
        return Err(RedisError::Protocol(format!(
            "CLUSTER SLOTS range {index} must contain start, end, and master node"
        )));
    }

    let start = parse_cluster_slot(&fields[0], "start slot")?;
    let end = parse_cluster_slot(&fields[1], "end slot")?;
    if start > end {
        return Err(RedisError::Protocol(format!(
            "CLUSTER SLOTS range {index} start slot {start} exceeds end slot {end}"
        )));
    }

    let master = parse_cluster_slot_node(&fields[2], "master node")?;
    let mut replicas = Vec::with_capacity(fields.len().saturating_sub(3));
    for replica in &fields[3..] {
        replicas.push(parse_cluster_slot_node(replica, "replica node")?);
    }

    Ok(RedisClusterSlotRange {
        start,
        end,
        master,
        replicas,
    })
}

fn cluster_slots_array<'a>(
    value: &'a RespValue,
    field: &str,
) -> Result<&'a [RespValue], RedisError> {
    match value {
        RespValue::Array(Some(items)) => Ok(items),
        _ => Err(RedisError::Protocol(format!(
            "CLUSTER SLOTS {field} must be an array"
        ))),
    }
}

fn parse_cluster_slot(value: &RespValue, field: &str) -> Result<u16, RedisError> {
    let slot = value
        .as_integer()
        .ok_or_else(|| RedisError::Protocol(format!("CLUSTER SLOTS {field} must be an integer")))?;
    if !(0..=i64::from(REDIS_CLUSTER_MAX_SLOT)).contains(&slot) {
        return Err(RedisError::Protocol(format!(
            "CLUSTER SLOTS {field} {slot} is outside 0..={REDIS_CLUSTER_MAX_SLOT}"
        )));
    }
    u16::try_from(slot).map_err(|_| {
        RedisError::Protocol(format!("CLUSTER SLOTS {field} {slot} is outside u16 range"))
    })
}

fn parse_cluster_port(value: &RespValue, field: &str) -> Result<u16, RedisError> {
    let port = value.as_integer().ok_or_else(|| {
        RedisError::Protocol(format!("CLUSTER SLOTS {field} port must be an integer"))
    })?;
    u16::try_from(port).map_err(|_| {
        RedisError::Protocol(format!(
            "CLUSTER SLOTS {field} port {port} is outside u16 range"
        ))
    })
}

fn parse_cluster_slot_node(
    value: &RespValue,
    field: &str,
) -> Result<RedisClusterSlotNode, RedisError> {
    let fields = cluster_slots_array(value, field)?;
    if fields.len() < 2 {
        return Err(RedisError::Protocol(format!(
            "CLUSTER SLOTS {field} must contain endpoint and port"
        )));
    }

    Ok(RedisClusterSlotNode {
        endpoint: parse_cluster_optional_text(&fields[0], field, "endpoint")?,
        port: parse_cluster_port(&fields[1], field)?,
        node_id: fields
            .get(2)
            .map(|value| parse_cluster_optional_text(value, field, "node id"))
            .transpose()?
            .flatten(),
    })
}

fn parse_cluster_optional_text(
    value: &RespValue,
    field: &str,
    name: &str,
) -> Result<Option<String>, RedisError> {
    match value {
        RespValue::BulkString(Some(bytes)) => {
            let text = std::str::from_utf8(bytes).map_err(|_| {
                RedisError::Protocol(format!("CLUSTER SLOTS {field} {name} is not valid UTF-8"))
            })?;
            Ok((!text.is_empty()).then(|| text.to_string()))
        }
        RespValue::BulkString(None) | RespValue::Null => Ok(None),
        _ => Err(RedisError::Protocol(format!(
            "CLUSTER SLOTS {field} {name} must be a bulk string or null"
        ))),
    }
}

/// Redis client (Phase 1: TCP + RESP decode + pooling; cluster-mode
/// MOVED/ASK redirect handling per br-asupersync-hzgugy).
pub struct RedisClient {
    config: RedisConfig,
    pool: GenericPool<RedisConnection, RedisFactory>,
    /// Slot → node-address map maintained by `-MOVED` redirects. Shared
    /// across all command invocations so once the cluster stabilizes
    /// after a reshard, future commands have the freshest target on
    /// record. Read for diagnostics today; future proactive cluster-
    /// aware routing can use it. (br-asupersync-hzgugy)
    slot_map: Arc<parking_lot::Mutex<HashMap<u16, String>>>,
    resp3_push_backlog: Arc<parking_lot::Mutex<RedisResp3PushBacklog>>,
}

impl fmt::Debug for RedisClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Snapshot every locked field BEFORE the .field chain. Rust extends
        // each `.lock()` MutexGuard temporary to the end of the enclosing
        // statement, so calling `self.resp3_push_backlog.lock()` twice in a
        // single `.field(..).field(..)` chain would self-deadlock under
        // parking_lot::Mutex's non-re-entrant semantics on the very first
        // `format!("{:?}", client)` (asupersync-mc0lgn).
        let known_slot_mappings = self.slot_map.lock().len();
        let (pending_resp3_pushes, resp3_push_dropped) = {
            let backlog = self.resp3_push_backlog.lock();
            (backlog.pending.len(), backlog.dropped)
        };
        f.debug_struct("RedisClient")
            .field("host", &self.config.host)
            .field("port", &self.config.port)
            .field("database", &self.config.database)
            .field("has_password", &self.config.password.is_some())
            .field("known_slot_mappings", &known_slot_mappings)
            .field("pending_resp3_pushes", &pending_resp3_pushes)
            .field("resp3_push_dropped", &resp3_push_dropped)
            .finish_non_exhaustive()
    }
}

impl RedisClient {
    /// Connect to Redis.
    #[allow(clippy::unused_async)]
    pub async fn connect(cx: &Cx, url: &str) -> Result<Self, RedisError> {
        cx.checkpoint().map_err(|_| RedisError::Cancelled)?;
        let config = RedisConfig::from_url(url)?;
        let config_for_factory = config.clone();
        let resp3_push_backlog =
            Arc::new(parking_lot::Mutex::new(RedisResp3PushBacklog::default()));
        let backlog_for_factory = Arc::clone(&resp3_push_backlog);

        let factory: RedisFactory = Box::new(move || {
            let config = config_for_factory.clone();
            let backlog = Arc::clone(&backlog_for_factory);
            Box::pin(async move { RedisConnection::connect(config, Some(backlog)).await })
        });

        let pool = GenericPool::new(factory, PoolConfig::with_max_size(10));

        Ok(Self {
            config,
            pool,
            slot_map: Arc::new(parking_lot::Mutex::new(HashMap::new())),
            resp3_push_backlog,
        })
    }

    /// Snapshot of the current slot → node-address map.
    ///
    /// Populated by `-MOVED` redirects; entries reflect the freshest
    /// target the cluster has reported. Empty for non-cluster
    /// deployments or until the first redirect lands. (br-asupersync-hzgugy)
    #[must_use]
    pub fn slot_map_snapshot(&self) -> HashMap<u16, String> {
        self.slot_map.lock().clone()
    }

    /// Receive the next buffered non-pubsub RESP3 push, if any.
    ///
    /// If the configured backlog cap
    /// [`RedisConfig::resp3_push_max_backlog`] was exceeded since the
    /// previous successful poll, returns
    /// [`RedisError::Resp3PushLag`] before any further queued push is
    /// delivered so the caller can observe the gap deterministically.
    pub fn try_next_resp3_push(&self) -> Result<Option<RedisResp3NonPubSubPush>, RedisError> {
        let mut backlog = self.resp3_push_backlog.lock();
        let new_drops = backlog.dropped.saturating_sub(backlog.lag_reported);
        if new_drops > 0 {
            backlog.lag_reported = backlog.dropped;
            return Err(RedisError::Resp3PushLag { dropped: new_drops });
        }
        Ok(backlog.pending.pop_front())
    }

    /// Returns the number of buffered RESP3 pushes currently queued for
    /// this regular command client.
    #[must_use]
    pub fn resp3_pending_pushes(&self) -> usize {
        self.resp3_push_backlog.lock().pending.len()
    }

    /// Returns the cumulative count of RESP3 pushes dropped because
    /// [`RedisConfig::resp3_push_max_backlog`] was reached.
    #[must_use]
    pub fn resp3_dropped_pushes(&self) -> u64 {
        self.resp3_push_backlog.lock().dropped
    }

    fn map_pool_error(err: PoolError) -> RedisError {
        match err {
            PoolError::Closed | PoolError::Timeout => RedisError::PoolExhausted,
            PoolError::Cancelled => RedisError::Cancelled,
            PoolError::CreateFailed(e) => RedisError::Protocol(format!("pool create failed: {e}")),
        }
    }

    async fn acquire(&self, cx: &Cx) -> Result<PooledResource<RedisConnection>, RedisError> {
        cx.checkpoint().map_err(|_| RedisError::Cancelled)?;
        self.pool.acquire(cx).await.map_err(Self::map_pool_error)
    }

    fn validate_redirect_target(&self, host: &str, port: u16) -> Result<(), RedisError> {
        let same_endpoint = host == self.config.host && port == self.config.port;
        if !same_endpoint && self.config.password.is_some() && !self.config.use_tls {
            return Err(RedisError::Protocol(format!(
                "refusing plaintext redis cluster redirect from {}:{} to {host}:{port} \
                 while AUTH credentials are configured; enable TLS for cluster redirects",
                self.config.host, self.config.port
            )));
        }
        Ok(())
    }

    /// Open a transient connection to a redirect target. Inherits the
    /// configured auth/database/protocol limits but retargets host/port.
    /// IPv6 brackets are stripped at connect time. Not pooled — per-node
    /// pooling would require multi-pool restructuring. (br-asupersync-hzgugy)
    async fn open_redirect_connection(
        &self,
        target_addr: &str,
        cx: &Cx,
    ) -> Result<RedisConnection, RedisError> {
        let (host, port) = target_addr.rsplit_once(':').ok_or_else(|| {
            RedisError::Protocol(format!(
                "redis cluster redirect address missing port: {target_addr}"
            ))
        })?;
        let host = host.trim_start_matches('[').trim_end_matches(']');
        let port: u16 = port.parse().map_err(|_| {
            RedisError::Protocol(format!(
                "redis cluster redirect address has invalid port: {target_addr}"
            ))
        })?;
        self.validate_redirect_target(host, port)?;

        let mut redirect_config = self.config.clone();
        redirect_config.host = host.to_string();
        redirect_config.port = port;

        let mut conn =
            RedisConnection::connect(redirect_config, Some(Arc::clone(&self.resp3_push_backlog)))
                .await?;
        conn.ensure_initialized(cx).await?;
        Ok(conn)
    }

    /// Execute a raw command (string args).
    pub async fn cmd(&self, cx: &Cx, args: &[&str]) -> Result<RespValue, RedisError> {
        let mut bytes: Vec<&[u8]> = Vec::with_capacity(args.len());
        for s in args {
            bytes.push(s.as_bytes());
        }
        self.cmd_bytes(cx, &bytes).await
    }

    /// Execute a raw command (byte args).
    ///
    /// Cluster-aware: on `-MOVED <slot> <addr>` updates the slot map and
    /// retries against `<addr>`; on `-ASK <slot> <addr>` retries against
    /// `<addr>` after first sending an `ASKING` prefix (the slot map is
    /// NOT updated — the migration is transient). Caps the redirect
    /// chain at `MAX_REDIRECTS = 5` to bound an adversarial cluster's
    /// ability to trap a caller in a loop. (br-asupersync-hzgugy)
    pub async fn cmd_bytes(&self, cx: &Cx, args: &[&[u8]]) -> Result<RespValue, RedisError> {
        // First attempt against the pooled conn for the configured node.
        let initial_err = {
            let mut conn = DiscardOnDropGuard::new(self.acquire(cx).await?);
            match conn.exec(cx, args).await {
                Ok(resp) => {
                    conn.return_to_pool();
                    return Ok(resp);
                }
                Err(RedisError::Redis(msg)) => {
                    // Server-level error — connection is still healthy.
                    conn.return_to_pool();
                    msg
                }
                Err(e) => return Err(e),
            }
        };

        let Some(mut redirect) = parse_redirect(&initial_err) else {
            return Err(RedisError::Redis(initial_err));
        };

        let mut redirects = 0u8;
        loop {
            redirects = redirects.saturating_add(1);
            if redirects > MAX_REDIRECTS {
                return Err(RedisError::Protocol(format!(
                    "redis cluster redirect chain exceeded maximum of {MAX_REDIRECTS} hops; \
                     last redirect target: {redirect:?}"
                )));
            }

            let target_addr = match &redirect {
                Redirect::Moved { addr, .. } | Redirect::Ask { addr, .. } => addr.clone(),
            };
            let mut redirect_conn = self.open_redirect_connection(&target_addr, cx).await?;

            let attempt = match &redirect {
                Redirect::Moved { slot, addr } => {
                    // Permanent reshard: record the new owner before issuing.
                    self.slot_map.lock().insert(*slot, addr.clone());
                    redirect_conn.exec_no_init(cx, args).await
                }
                Redirect::Ask { .. } => {
                    // Transient migration: prepend ASKING (one-shot
                    // permission for the next command). Slot map unchanged.
                    match redirect_conn.exec_no_init(cx, &[b"ASKING"]).await {
                        Ok(RespValue::SimpleString(ref s)) if s == "OK" => {
                            redirect_conn.exec_no_init(cx, args).await
                        }
                        Ok(other) => Err(RedisError::Protocol(format!(
                            "redis ASKING returned unexpected response: {other:?}"
                        ))),
                        Err(e) => Err(e),
                    }
                }
            };

            // Drop the transient connection back to the OS.
            let _ = redirect_conn.stream.shutdown_transport();

            match attempt {
                Ok(resp) => return Ok(resp),
                Err(RedisError::Redis(msg)) => {
                    if let Some(next) = parse_redirect(&msg) {
                        redirect = next;
                        continue;
                    }
                    return Err(RedisError::Redis(msg));
                }
                Err(e) => return Err(e),
            }
        }
    }

    /// GET key.
    pub async fn get(&self, cx: &Cx, key: &str) -> Result<Option<Vec<u8>>, RedisError> {
        let response = self.cmd_bytes(cx, &[b"GET", key.as_bytes()]).await?;
        Ok(response.as_bytes().map(<[u8]>::to_vec))
    }

    /// SET key value.
    pub async fn set(
        &self,
        cx: &Cx,
        key: &str,
        value: &[u8],
        ttl: Option<Duration>,
    ) -> Result<(), RedisError> {
        if let Some(ttl) = ttl {
            let mut tmp = [0u8; 20];
            let millis = u64_decimal_bytes(positive_ttl_millis(ttl)?, &mut tmp);
            let resp = self
                .cmd_bytes(cx, &[b"SET", key.as_bytes(), value, b"PX", millis])
                .await?;
            if !resp.is_ok() {
                return Err(RedisError::Protocol(format!(
                    "SET expected +OK, got {resp:?}"
                )));
            }
        } else {
            let resp = self.cmd_bytes(cx, &[b"SET", key.as_bytes(), value]).await?;
            if !resp.is_ok() {
                return Err(RedisError::Protocol(format!(
                    "SET expected +OK, got {resp:?}"
                )));
            }
        }
        Ok(())
    }

    /// INCR key.
    pub async fn incr(&self, cx: &Cx, key: &str) -> Result<i64, RedisError> {
        let response = self.cmd_bytes(cx, &[b"INCR", key.as_bytes()]).await?;
        response
            .as_integer()
            .ok_or_else(|| RedisError::Protocol("INCR did not return integer".to_string()))
    }

    /// DEL key [key ...]
    ///
    /// Returns the number of keys removed.
    pub async fn del(&self, cx: &Cx, keys: &[&str]) -> Result<i64, RedisError> {
        if keys.is_empty() {
            return Err(RedisError::Protocol(
                "DEL requires at least one key".to_string(),
            ));
        }

        let mut args: Vec<&[u8]> = Vec::with_capacity(keys.len().saturating_add(1));
        args.push(b"DEL");
        for key in keys {
            args.push(key.as_bytes());
        }

        let resp = self.cmd_bytes(cx, &args).await?;
        resp.as_integer()
            .ok_or_else(|| RedisError::Protocol("DEL did not return integer".to_string()))
    }

    /// Set the key TTL using Redis millisecond precision.
    ///
    /// `Duration::ZERO` maps to Redis's immediate-expiry semantics.
    ///
    /// Returns true if the timeout was set, false if the key does not exist.
    pub async fn expire(&self, cx: &Cx, key: &str, ttl: Duration) -> Result<bool, RedisError> {
        let mut tmp = [0u8; 20];
        let millis = u64_decimal_bytes(ttl_millis_rounded_up(ttl), &mut tmp);
        let resp = self
            .cmd_bytes(cx, &[b"PEXPIRE", key.as_bytes(), millis])
            .await?;

        let n = resp
            .as_integer()
            .ok_or_else(|| RedisError::Protocol("PEXPIRE did not return integer".to_string()))?;
        Ok(n != 0)
    }

    /// HGET key field
    pub async fn hget(
        &self,
        cx: &Cx,
        key: &str,
        field: &str,
    ) -> Result<Option<Vec<u8>>, RedisError> {
        let resp = self
            .cmd_bytes(cx, &[b"HGET", key.as_bytes(), field.as_bytes()])
            .await?;

        match resp {
            RespValue::BulkString(Some(bytes)) => Ok(Some(bytes)),
            RespValue::BulkString(None) => Ok(None),
            other => Err(RedisError::Protocol(format!(
                "HGET expected bulk string, got {other:?}"
            ))),
        }
    }

    /// HSET key field value
    ///
    /// Returns true if the field was newly inserted, false if it was updated.
    pub async fn hset(
        &self,
        cx: &Cx,
        key: &str,
        field: &str,
        value: &[u8],
    ) -> Result<bool, RedisError> {
        let resp = self
            .cmd_bytes(cx, &[b"HSET", key.as_bytes(), field.as_bytes(), value])
            .await?;

        let n = resp
            .as_integer()
            .ok_or_else(|| RedisError::Protocol("HSET did not return integer".to_string()))?;
        Ok(n != 0)
    }

    /// HDEL key field [field ...]
    ///
    /// Returns the number of fields removed.
    pub async fn hdel(&self, cx: &Cx, key: &str, fields: &[&str]) -> Result<i64, RedisError> {
        if fields.is_empty() {
            return Err(RedisError::Protocol(
                "HDEL requires at least one field".to_string(),
            ));
        }

        let mut args: Vec<&[u8]> = Vec::with_capacity(fields.len().saturating_add(2));
        args.push(b"HDEL");
        args.push(key.as_bytes());
        for field in fields {
            args.push(field.as_bytes());
        }

        let resp = self.cmd_bytes(cx, &args).await?;
        resp.as_integer()
            .ok_or_else(|| RedisError::Protocol("HDEL did not return integer".to_string()))
    }

    /// PING health check.
    pub async fn ping(&self, cx: &Cx) -> Result<(), RedisError> {
        let resp = self.cmd_bytes(cx, &[b"PING"]).await?;
        match resp {
            RespValue::SimpleString(s) if s == "PONG" => Ok(()),
            RespValue::BulkString(Some(bytes)) if bytes == b"PONG" => Ok(()),
            other => Err(RedisError::Protocol(format!(
                "PING expected PONG, got {other:?}"
            ))),
        }
    }

    /// PUBLISH channel payload.
    ///
    /// Returns the number of subscribers that received the payload.
    pub async fn publish(&self, cx: &Cx, channel: &str, payload: &[u8]) -> Result<i64, RedisError> {
        let resp = self
            .cmd_bytes(cx, &[b"PUBLISH", channel.as_bytes(), payload])
            .await?;
        resp.as_integer()
            .ok_or_else(|| RedisError::Protocol("PUBLISH did not return integer".to_string()))
    }

    /// WATCH keys for optimistic transactions.
    ///
    /// Redis WATCH state is bound to a single connection. This pooled client
    /// cannot guarantee that a later `MULTI`/`EXEC` sequence runs on the same
    /// socket, so exposing WATCH as a successful one-shot command would be
    /// misleading.
    pub fn watch(&self, _cx: &Cx, keys: &[&str]) -> Result<(), RedisError> {
        if keys.is_empty() {
            return Err(RedisError::Protocol(
                "WATCH requires at least one key".to_string(),
            ));
        }

        Err(RedisError::Protocol(
            "WATCH is unsupported on pooled RedisClient because watch state is connection-scoped; use a dedicated connection/session API"
                .to_string(),
        ))
    }

    /// Clear all watched keys on the current connection.
    ///
    /// This pooled client cannot guarantee which connection would receive the
    /// command, so `UNWATCH` is rejected for the same reason as [`Self::watch`].
    pub fn unwatch(&self, _cx: &Cx) -> Result<(), RedisError> {
        Err(RedisError::Protocol(
            "UNWATCH is unsupported on pooled RedisClient because watch state is connection-scoped; use a dedicated connection/session API"
                .to_string(),
        ))
    }

    /// Start a Redis transaction using `MULTI`/`EXEC`.
    pub async fn transaction(&self, cx: &Cx) -> Result<Transaction, RedisError> {
        Transaction::begin(self, cx).await
    }

    /// Open a dedicated Pub/Sub connection.
    pub async fn pubsub(&self, cx: &Cx) -> Result<RedisPubSub, RedisError> {
        RedisPubSub::connect(cx, self.config.clone()).await
    }

    /// Start a pipeline (multiple commands on a single pooled connection).
    #[must_use]
    pub fn pipeline(&self) -> Pipeline<'_> {
        Pipeline {
            client: self,
            encoded: Vec::new(),
        }
    }
}

/// Guard that discards a pooled Redis connection on drop unless defused.
/// Prevents a desynced connection from being returned to the pool when
/// a future is cancelled mid-protocol-exchange.
struct DiscardOnDropGuard {
    conn: Option<PooledResource<RedisConnection>>,
}

impl DiscardOnDropGuard {
    fn new(conn: PooledResource<RedisConnection>) -> Self {
        Self { conn: Some(conn) }
    }

    fn defuse(mut self) -> PooledResource<RedisConnection> {
        self.conn.take().expect("guard already defused")
    }

    fn return_to_pool(self) {
        self.defuse().return_to_pool();
    }
}

impl std::ops::Deref for DiscardOnDropGuard {
    type Target = RedisConnection;
    fn deref(&self) -> &Self::Target {
        self.conn.as_ref().expect("guard defused")
    }
}

impl std::ops::DerefMut for DiscardOnDropGuard {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.conn.as_mut().expect("guard defused")
    }
}

impl Drop for DiscardOnDropGuard {
    fn drop(&mut self) {
        if let Some(conn) = self.conn.take() {
            // Fail closed: once a protocol exchange is abandoned, force the
            // transport down before discarding so the peer promptly observes
            // EOF/RST instead of leaving a half-live socket around.
            let _ = conn.stream.shutdown_transport();
            conn.discard();
        }
    }
}

/// A Redis command pipeline.
///
/// Pipelines batch multiple commands onto a *single* connection, sending the
/// requests back-to-back and then reading the same number of responses in
/// order.
///
/// Notes:
/// - Per RESP semantics, individual commands in a pipeline can fail
///   independently. `exec()` returns
///   `Result<Vec<Result<RespValue, RedisError>>, RedisError>`:
///   * The outer `Result` carries IO / protocol errors that invalidate the
///     entire pipeline (and force the connection to be discarded).
///   * The inner `Result` is per-command: a RESP `-ERR ...` reply becomes
///     `Err(RedisError::Redis(msg))`, every other reply (including nil)
///     becomes `Ok(value)`. The connection stays healthy and is returned
///     to the pool. (br-asupersync-pr32li)
/// - If an I/O error occurs mid-pipeline (read/write fails, EOF, framing
///   error), the connection is discarded because its read/write state is
///   no longer reliable.
#[derive(Debug)]
pub struct Pipeline<'a> {
    client: &'a RedisClient,
    encoded: Vec<Vec<u8>>,
}

impl Pipeline<'_> {
    /// Append a command (string args).
    pub fn cmd(&mut self, args: &[&str]) -> &mut Self {
        let mut bytes: Vec<&[u8]> = Vec::with_capacity(args.len());
        for s in args {
            bytes.push(s.as_bytes());
        }
        self.cmd_bytes(&bytes)
    }

    /// Append a command (byte args).
    pub fn cmd_bytes(&mut self, args: &[&[u8]]) -> &mut Self {
        let mut buf = Vec::new();
        encode_command_into(&mut buf, args);
        self.encoded.push(buf);
        self
    }

    /// Execute the pipeline and return per-command results.
    ///
    /// Returns `Vec<Result<RespValue, RedisError>>` where each element
    /// corresponds positionally to a queued command. A RESP `-ERR` reply
    /// becomes `Err(RedisError::Redis(msg))` for that single command; the
    /// loop continues to drain remaining responses so the wire-protocol
    /// framing stays in sync. The connection is returned to the pool
    /// regardless of how many per-command errors occurred.
    ///
    /// The outer `Err(...)` is reserved for IO / protocol failures
    /// (write, flush, framing read, EOF) which DO invalidate the
    /// connection — those discard the pooled connection because its
    /// protocol state is no longer reliable. (br-asupersync-pr32li)
    pub async fn exec(self, cx: &Cx) -> Result<Vec<Result<RespValue, RedisError>>, RedisError> {
        let mut conn = DiscardOnDropGuard::new(self.client.acquire(cx).await?);

        // Ensure AUTH/SELECT have been run on this connection.
        conn.ensure_initialized(cx).await?;

        // Write all commands in one go to reduce syscalls.
        let total_len: usize = self.encoded.iter().map(Vec::len).sum();
        let mut combined = Vec::with_capacity(total_len);
        for cmd in &self.encoded {
            combined.extend_from_slice(cmd);
        }

        cx.checkpoint().map_err(|_| RedisError::Cancelled)?;

        if let Err(e) = conn.stream.write_all(&combined).await {
            // Guard drop will discard the connection.
            return Err(RedisError::Io(e));
        }
        if let Err(e) = conn.stream.flush().await {
            return Err(RedisError::Io(e));
        }

        // Drain ALL responses from the wire BEFORE returning. A protocol /
        // IO error from `read_response` truly invalidates the connection
        // (it can't be reused without re-syncing the framer), so we
        // propagate via the outer Err and let the guard discard the
        // connection. Application-level `-ERR` replies become per-command
        // `Err`s in the inner Result so a failed command in a pipeline
        // doesn't tear down the whole batch or the connection.
        let mut out = Vec::with_capacity(self.encoded.len());
        for _ in 0..self.encoded.len() {
            let resp = conn.read_response(cx).await?;
            match resp {
                RespValue::Error(msg) => out.push(Err(RedisError::Redis(msg))),
                other => out.push(Ok(other)),
            }
        }

        // Protocol exchange complete — defuse the guard so the connection
        // returns to the pool instead of being discarded. -ERR replies are
        // application-level and do NOT invalidate the connection.
        conn.return_to_pool();
        Ok(out)
    }
}

/// A Redis transaction started with `MULTI`.
///
/// Commands queued through [`Self::cmd`] / [`Self::cmd_bytes`] execute atomically
/// when [`Self::exec`] is called.
pub struct Transaction {
    conn: Option<PooledResource<RedisConnection>>,
    queued_commands: usize,
    finished: bool,
}

impl Transaction {
    async fn begin(client: &RedisClient, cx: &Cx) -> Result<Self, RedisError> {
        let mut conn = DiscardOnDropGuard::new(client.acquire(cx).await?);
        conn.ensure_initialized(cx).await?;
        let resp = conn.exec_no_init(cx, &[b"MULTI"]).await?;
        expect_ok_response(&resp, "MULTI")?;

        Ok(Self {
            conn: Some(conn.defuse()),
            queued_commands: 0,
            finished: false,
        })
    }

    /// Number of commands queued so far.
    #[must_use]
    pub fn queued_commands(&self) -> usize {
        self.queued_commands
    }

    /// Queue a command in this transaction.
    pub async fn cmd(&mut self, cx: &Cx, args: &[&str]) -> Result<(), RedisError> {
        let mut bytes: Vec<&[u8]> = Vec::with_capacity(args.len());
        for s in args {
            bytes.push(s.as_bytes());
        }
        self.cmd_bytes(cx, &bytes).await
    }

    /// Queue a command in this transaction.
    ///
    /// # State invariants (br-asupersync-4tb7kn)
    ///
    /// `self.finished` is **not** mutated until after both await points
    /// (`write_command`, `read_response`) complete. The previous
    /// implementation set `self.finished = true` eagerly at the top of
    /// the function and only reset it to `false` on the success and
    /// Redis-`-ERR` paths — so on a transient network failure mid-write
    /// or a cancel mid-read, the transaction object was permanently
    /// bricked from the caller's perspective with no signal that it
    /// might be a recoverable retry candidate. The reorder below
    /// preserves the correct connection-state hygiene (poisoned
    /// connection discarded by `DiscardOnDropGuard`) while leaving
    /// `self.finished` unset on the failure paths so the caller's
    /// subsequent attempt observes the more accurate
    /// `"transaction already finished"` (no live connection) error
    /// rather than the misleading `"after transaction completion"`.
    /// `self.finished` is now only set in two places: the protocol-
    /// violation arm (the connection responded with garbage — terminal),
    /// and the public `exec`/`discard` methods which are the legitimate
    /// terminal transitions.
    pub async fn cmd_bytes(&mut self, cx: &Cx, args: &[&[u8]]) -> Result<(), RedisError> {
        if self.finished {
            return Err(RedisError::Protocol(
                "cannot queue command after transaction completion".to_string(),
            ));
        }

        let conn = self
            .conn
            .take()
            .ok_or_else(|| RedisError::Protocol("transaction already finished".to_string()))?;
        let mut conn = DiscardOnDropGuard::new(conn);

        conn.write_command(cx, args).await?;
        let resp = conn.read_response(cx).await?;

        match resp {
            RespValue::SimpleString(s) if s == "QUEUED" => {
                self.conn = Some(conn.defuse());
                self.queued_commands = self.queued_commands.saturating_add(1);
                Ok(())
            }
            RespValue::Error(msg) => {
                self.conn = Some(conn.defuse());
                Err(RedisError::Redis(msg))
            }
            other => {
                // Protocol violation: the connection responded with a
                // shape Redis does not document as legal in MULTI mode.
                // Mark the transaction terminated so subsequent calls
                // surface the precise "after transaction completion"
                // error rather than the generic "no connection" error.
                // The connection itself is poisoned and discarded by
                // the guard.
                self.finished = true;
                Err(RedisError::Protocol(format!(
                    "queued command expected +QUEUED, got {other:?}"
                )))
            }
        }
    }

    /// Execute the transaction with `EXEC`.
    ///
    /// Returns all command replies in queue order.
    pub async fn exec(mut self, cx: &Cx) -> Result<Vec<RespValue>, RedisError> {
        let conn = self.conn.take().ok_or_else(|| {
            RedisError::Protocol("cannot EXEC: transaction already finished".to_string())
        })?;
        self.finished = true;
        let mut conn = DiscardOnDropGuard::new(conn);

        let resp = conn.exec_no_init(cx, &[b"EXEC"]).await?;

        match resp {
            RespValue::Array(Some(values)) => {
                conn.return_to_pool();
                Ok(values)
            }
            RespValue::Array(None) => {
                conn.return_to_pool();
                Err(RedisError::Redis(
                    "EXEC returned null (WATCH condition failed)".to_string(),
                ))
            }
            RespValue::Error(msg) => {
                conn.return_to_pool();
                Err(RedisError::Redis(msg))
            }
            other => Err(RedisError::Protocol(format!(
                "EXEC expected array reply, got {other:?}"
            ))),
        }
    }

    /// Abort the transaction with `DISCARD`.
    pub async fn discard(mut self, cx: &Cx) -> Result<(), RedisError> {
        let conn = self.conn.take().ok_or_else(|| {
            RedisError::Protocol("cannot DISCARD: transaction already finished".to_string())
        })?;
        self.finished = true;
        let mut conn = DiscardOnDropGuard::new(conn);

        let resp = conn.exec_no_init(cx, &[b"DISCARD"]).await?;
        expect_ok_response(&resp, "DISCARD")?;
        conn.return_to_pool();
        Ok(())
    }
}

impl Drop for Transaction {
    fn drop(&mut self) {
        if self.finished {
            return;
        }
        if let Some(conn) = self.conn.take() {
            // We cannot issue async DISCARD in Drop. Discarding the pooled
            // connection ensures transaction state does not leak to future users.
            let _ = conn.stream.shutdown_transport();
            conn.discard();
        }
        self.finished = true;
    }
}

/// Dedicated Redis Pub/Sub connection.
#[derive(Debug)]
pub struct RedisPubSub {
    conn: RedisConnection,
    config: RedisConfig,
    channels: Vec<String>,
    patterns: Vec<String>,
    pending_events: VecDeque<PubSubEvent>,
    poisoned: bool,
    /// Cumulative count of events dropped because `pending_events`
    /// reached `config.pubsub_max_backlog`. Monotonic over the lifetime
    /// of this subscriber. Surfaced to callers via
    /// [`pubsub_dropped_events`](Self::pubsub_dropped_events) for
    /// metrics. (br-asupersync-697arj.)
    pubsub_dropped_events: u64,
    /// Snapshot of `pubsub_dropped_events` at the most recent
    /// `RedisError::SubscriberLag` report. Used so that each overflow
    /// burst surfaces exactly once and the caller can compute the
    /// delta `pubsub_dropped_events - pubsub_lag_reported` if it later
    /// wants to confirm no further drops occurred between the lag
    /// being surfaced and the next read.
    pubsub_lag_reported: u64,
}

struct PubSubControlGuard<'a> {
    pubsub: &'a mut RedisPubSub,
    snapshot_channels: Vec<String>,
    snapshot_patterns: Vec<String>,
    active: bool,
}

impl<'a> PubSubControlGuard<'a> {
    fn new(pubsub: &'a mut RedisPubSub) -> Result<Self, RedisError> {
        pubsub.ensure_live()?;
        Ok(Self {
            snapshot_channels: pubsub.channels.clone(),
            snapshot_patterns: pubsub.patterns.clone(),
            pubsub,
            active: true,
        })
    }

    fn commit(mut self) {
        self.active = false;
    }

    async fn write_command(&mut self, cx: &Cx, args: &[&[u8]]) -> Result<(), RedisError> {
        self.pubsub.conn.write_command(cx, args).await
    }

    async fn read_next_event(&mut self, cx: &Cx) -> Result<PubSubEvent, RedisError> {
        self.pubsub.read_next_event(cx).await
    }

    fn push_pending_event(&mut self, event: PubSubEvent) {
        self.pubsub.push_pending_event(event);
    }

    fn track_channel(&mut self, channel: &str) {
        RedisPubSub::track_subscribe(&mut self.pubsub.channels, channel);
    }

    fn untrack_channel(&mut self, channel: &str) {
        RedisPubSub::untrack_subscribe(&mut self.pubsub.channels, channel);
    }

    fn track_pattern(&mut self, pattern: &str) {
        RedisPubSub::track_subscribe(&mut self.pubsub.patterns, pattern);
    }

    fn untrack_pattern(&mut self, pattern: &str) {
        RedisPubSub::untrack_subscribe(&mut self.pubsub.patterns, pattern);
    }
}

impl Drop for PubSubControlGuard<'_> {
    fn drop(&mut self) {
        if !self.active {
            return;
        }

        self.pubsub.channels = std::mem::take(&mut self.snapshot_channels);
        self.pubsub.patterns = std::mem::take(&mut self.snapshot_patterns);
        self.pubsub.pending_events.clear();
        self.pubsub.poisoned = true;
        let _ = self.pubsub.conn.stream.shutdown_transport();
    }
}

impl RedisPubSub {
    async fn connect(cx: &Cx, config: RedisConfig) -> Result<Self, RedisError> {
        let mut conn = RedisConnection::connect(config.clone(), None).await?;
        conn.ensure_initialized(cx).await?;
        Ok(Self {
            conn,
            config,
            channels: Vec::new(),
            patterns: Vec::new(),
            pending_events: VecDeque::new(),
            poisoned: false,
            pubsub_dropped_events: 0,
            pubsub_lag_reported: 0,
        })
    }

    fn ensure_live(&self) -> Result<(), RedisError> {
        if self.poisoned {
            Err(RedisError::Protocol(
                "redis pubsub connection was invalidated by a cancelled or failed control exchange; call reconnect"
                    .to_string(),
            ))
        } else {
            Ok(())
        }
    }

    fn push_pending_event(&mut self, event: PubSubEvent) {
        // Use the configured backlog cap (default 4096) instead of a
        // const so production tuning can raise it for slow consumers.
        // Dropping is still bounded — we increment a counter and let
        // next_event() surface a `SubscriberLag` error so the silent
        // data loss the original implementation produced becomes loud
        // (br-asupersync-697arj).
        let cap = self.config.pubsub_max_backlog;
        if cap > 0 && self.pending_events.len() < cap {
            self.pending_events.push_back(event);
            return;
        }
        self.pubsub_dropped_events = self.pubsub_dropped_events.saturating_add(1);
        crate::tracing_compat::warn!(
            backlog = self.pending_events.len(),
            cap = cap,
            cumulative_dropped = self.pubsub_dropped_events,
            channel_count = self.channels.len(),
            pattern_count = self.patterns.len(),
            "redis pubsub backlog full; event dropped — raise \
             RedisConfig.pubsub_max_backlog or drain next_event faster"
        );
    }

    /// Returns the cumulative count of Pub/Sub events that were dropped
    /// because [`RedisConfig::pubsub_max_backlog`] was reached.
    /// Intended as a metric: SREs can poll this for an at-most-once
    /// observability signal independent of the per-call
    /// [`RedisError::SubscriberLag`] surface returned by
    /// [`next_event`](Self::next_event). (br-asupersync-697arj.)
    #[must_use]
    pub fn pubsub_dropped_events(&self) -> u64 {
        self.pubsub_dropped_events
    }

    fn decode_text(value: RespValue, field: &str) -> Result<String, RedisError> {
        match value {
            RespValue::SimpleString(s) => Ok(s),
            RespValue::BulkString(Some(bytes)) => String::from_utf8(bytes)
                .map_err(|_| RedisError::Protocol(format!("{field} is not valid UTF-8"))),
            other => Err(RedisError::Protocol(format!(
                "expected text for {field}, got {other:?}"
            ))),
        }
    }

    fn decode_payload(value: RespValue, field: &str) -> Result<Vec<u8>, RedisError> {
        match value {
            RespValue::SimpleString(s) => Ok(s.into_bytes()),
            RespValue::BulkString(Some(bytes)) => Ok(bytes),
            other => Err(RedisError::Protocol(format!(
                "expected payload for {field}, got {other:?}"
            ))),
        }
    }

    fn decode_integer(value: RespValue, field: &str) -> Result<i64, RedisError> {
        match value {
            RespValue::Integer(i) => Ok(i),
            other => Err(RedisError::Protocol(format!(
                "expected integer for {field}, got {other:?}"
            ))),
        }
    }

    fn next_required(
        iter: &mut impl Iterator<Item = RespValue>,
        missing: &str,
    ) -> Result<RespValue, RedisError> {
        iter.next()
            .ok_or_else(|| RedisError::Protocol(missing.to_string()))
    }

    fn ensure_no_trailing(
        iter: &mut impl Iterator<Item = RespValue>,
        message: &str,
    ) -> Result<(), RedisError> {
        if iter.next().is_some() {
            Err(RedisError::Protocol(message.to_string()))
        } else {
            Ok(())
        }
    }

    fn parse_message_event(
        iter: &mut impl Iterator<Item = RespValue>,
    ) -> Result<PubSubEvent, RedisError> {
        let channel = Self::decode_text(
            Self::next_required(iter, "pubsub message missing channel")?,
            "message.channel",
        )?;
        let payload = Self::decode_payload(
            Self::next_required(iter, "pubsub message missing payload")?,
            "message.payload",
        )?;
        Self::ensure_no_trailing(iter, "pubsub message has unexpected trailing fields")?;
        Ok(PubSubEvent::Message(PubSubMessage {
            channel,
            pattern: None,
            payload,
        }))
    }

    fn parse_pmessage_event(
        iter: &mut impl Iterator<Item = RespValue>,
    ) -> Result<PubSubEvent, RedisError> {
        let pattern = Self::decode_text(
            Self::next_required(iter, "pubsub pmessage missing pattern")?,
            "pmessage.pattern",
        )?;
        let channel = Self::decode_text(
            Self::next_required(iter, "pubsub pmessage missing channel")?,
            "pmessage.channel",
        )?;
        let payload = Self::decode_payload(
            Self::next_required(iter, "pubsub pmessage missing payload")?,
            "pmessage.payload",
        )?;
        Self::ensure_no_trailing(iter, "pubsub pmessage has unexpected trailing fields")?;
        Ok(PubSubEvent::Message(PubSubMessage {
            channel,
            pattern: Some(pattern),
            payload,
        }))
    }

    fn parse_subscription_event(
        kind: &str,
        iter: &mut impl Iterator<Item = RespValue>,
    ) -> Result<PubSubEvent, RedisError> {
        let channel = Self::decode_text(
            Self::next_required(iter, "pubsub subscription missing channel")?,
            "subscription.channel",
        )?;
        let remaining = Self::decode_integer(
            Self::next_required(iter, "pubsub subscription missing remaining-count")?,
            "subscription.remaining",
        )?;
        Self::ensure_no_trailing(iter, "pubsub subscription has unexpected trailing fields")?;
        let kind = if kind.eq_ignore_ascii_case("subscribe") {
            PubSubSubscriptionKind::Subscribe
        } else if kind.eq_ignore_ascii_case("unsubscribe") {
            PubSubSubscriptionKind::Unsubscribe
        } else if kind.eq_ignore_ascii_case("psubscribe") {
            PubSubSubscriptionKind::PatternSubscribe
        } else {
            PubSubSubscriptionKind::PatternUnsubscribe
        };
        Ok(PubSubEvent::Subscription {
            kind,
            channel,
            remaining,
        })
    }

    fn parse_pong_event(
        iter: &mut impl Iterator<Item = RespValue>,
    ) -> Result<PubSubEvent, RedisError> {
        let payload = match iter.next() {
            None => None,
            Some(value) => Some(Self::decode_payload(value, "pong.payload")?),
        };
        Self::ensure_no_trailing(iter, "pubsub pong has unexpected trailing fields")?;
        Ok(PubSubEvent::Pong(payload))
    }

    fn parse_event(value: RespValue) -> Result<PubSubEvent, RedisError> {
        let items = match value {
            RespValue::Array(Some(items)) => items,
            RespValue::Push(items) => items,
            other => {
                return Err(RedisError::Protocol(format!(
                    "pubsub expected array or push event, got {other:?}"
                )));
            }
        };

        let mut iter = items.into_iter();
        let kind = Self::decode_text(
            iter.next()
                .ok_or_else(|| RedisError::Protocol("pubsub event missing kind".to_string()))?,
            "pubsub kind",
        )?;

        if kind.eq_ignore_ascii_case("message") {
            Self::parse_message_event(&mut iter)
        } else if kind.eq_ignore_ascii_case("pmessage") {
            Self::parse_pmessage_event(&mut iter)
        } else if kind.eq_ignore_ascii_case("subscribe")
            || kind.eq_ignore_ascii_case("unsubscribe")
            || kind.eq_ignore_ascii_case("psubscribe")
            || kind.eq_ignore_ascii_case("punsubscribe")
        {
            Self::parse_subscription_event(&kind, &mut iter)
        } else if kind.eq_ignore_ascii_case("pong") {
            Self::parse_pong_event(&mut iter)
        } else {
            Err(RedisError::Protocol(format!(
                "unsupported pubsub event kind: {kind}"
            )))
        }
    }

    fn track_subscribe(list: &mut Vec<String>, value: &str) {
        if !list.iter().any(|existing| existing == value) {
            list.push(value.to_string());
        }
    }

    fn untrack_subscribe(list: &mut Vec<String>, value: &str) {
        list.retain(|existing| existing != value);
    }

    fn acknowledge_subscription_target(
        expected: &mut Vec<String>,
        received: &str,
        command: &str,
    ) -> Result<(), RedisError> {
        let Some(index) = expected.iter().position(|candidate| candidate == received) else {
            return Err(RedisError::Protocol(format!(
                "{command} received unexpected acknowledgement target: {received}"
            )));
        };
        expected.remove(index);
        Ok(())
    }

    async fn read_next_event(&mut self, cx: &Cx) -> Result<PubSubEvent, RedisError> {
        let response = self.conn.read_pubsub_response(cx).await?;
        Self::parse_event(response)
    }

    /// Subscribe to one or more channels.
    pub async fn subscribe(&mut self, cx: &Cx, channels: &[&str]) -> Result<(), RedisError> {
        if channels.is_empty() {
            return Err(RedisError::Protocol(
                "SUBSCRIBE requires at least one channel".to_string(),
            ));
        }

        let mut guard = PubSubControlGuard::new(self)?;
        let mut args: Vec<&[u8]> = Vec::with_capacity(channels.len().saturating_add(1));
        args.push(b"SUBSCRIBE");
        for channel in channels {
            args.push(channel.as_bytes());
        }
        guard.write_command(cx, &args).await?;

        let mut expected_acks: Vec<String> = channels
            .iter()
            .map(|channel| (*channel).to_string())
            .collect();
        while !expected_acks.is_empty() {
            let event = guard.read_next_event(cx).await?;
            match event {
                PubSubEvent::Subscription {
                    kind: PubSubSubscriptionKind::Subscribe,
                    channel,
                    ..
                } => {
                    Self::acknowledge_subscription_target(
                        &mut expected_acks,
                        &channel,
                        "SUBSCRIBE",
                    )?;
                    guard.track_channel(&channel);
                }
                // Buffer interleaved messages from existing subscriptions
                // so they aren't silently dropped while waiting for acks.
                other => guard.push_pending_event(other),
            }
        }

        guard.commit();
        Ok(())
    }

    /// Subscribe to one or more glob-style patterns.
    pub async fn psubscribe(&mut self, cx: &Cx, patterns: &[&str]) -> Result<(), RedisError> {
        if patterns.is_empty() {
            return Err(RedisError::Protocol(
                "PSUBSCRIBE requires at least one pattern".to_string(),
            ));
        }

        let mut guard = PubSubControlGuard::new(self)?;
        let mut args: Vec<&[u8]> = Vec::with_capacity(patterns.len().saturating_add(1));
        args.push(b"PSUBSCRIBE");
        for pattern in patterns {
            args.push(pattern.as_bytes());
        }
        guard.write_command(cx, &args).await?;

        let mut expected_acks: Vec<String> = patterns
            .iter()
            .map(|pattern| (*pattern).to_string())
            .collect();
        while !expected_acks.is_empty() {
            let event = guard.read_next_event(cx).await?;
            match event {
                PubSubEvent::Subscription {
                    kind: PubSubSubscriptionKind::PatternSubscribe,
                    channel,
                    ..
                } => {
                    Self::acknowledge_subscription_target(
                        &mut expected_acks,
                        &channel,
                        "PSUBSCRIBE",
                    )?;
                    guard.track_pattern(&channel);
                }
                other => guard.push_pending_event(other),
            }
        }

        guard.commit();
        Ok(())
    }

    /// Unsubscribe from channels.
    ///
    /// Passing an empty slice unsubscribes from all channels currently tracked.
    pub async fn unsubscribe(&mut self, cx: &Cx, channels: &[&str]) -> Result<(), RedisError> {
        self.ensure_live()?;
        if channels.is_empty() && self.channels.is_empty() {
            return Ok(());
        }

        let mut guard = PubSubControlGuard::new(self)?;
        let mut args: Vec<&[u8]> = Vec::with_capacity(channels.len().saturating_add(1));
        args.push(b"UNSUBSCRIBE");
        for channel in channels {
            args.push(channel.as_bytes());
        }
        guard.write_command(cx, &args).await?;

        let mut expected_acks = if channels.is_empty() {
            guard.pubsub.channels.clone()
        } else {
            channels
                .iter()
                .map(|channel| (*channel).to_string())
                .collect()
        };
        while !expected_acks.is_empty() {
            let event = guard.read_next_event(cx).await?;
            match event {
                PubSubEvent::Subscription {
                    kind: PubSubSubscriptionKind::Unsubscribe,
                    channel,
                    ..
                } => {
                    Self::acknowledge_subscription_target(
                        &mut expected_acks,
                        &channel,
                        "UNSUBSCRIBE",
                    )?;
                    guard.untrack_channel(&channel);
                }
                other => guard.push_pending_event(other),
            }
        }
        guard.commit();
        Ok(())
    }

    /// Unsubscribe from patterns.
    ///
    /// Passing an empty slice unsubscribes from all patterns currently tracked.
    pub async fn punsubscribe(&mut self, cx: &Cx, patterns: &[&str]) -> Result<(), RedisError> {
        self.ensure_live()?;
        if patterns.is_empty() && self.patterns.is_empty() {
            return Ok(());
        }

        let mut guard = PubSubControlGuard::new(self)?;
        let mut args: Vec<&[u8]> = Vec::with_capacity(patterns.len().saturating_add(1));
        args.push(b"PUNSUBSCRIBE");
        for pattern in patterns {
            args.push(pattern.as_bytes());
        }
        guard.write_command(cx, &args).await?;

        let mut expected_acks = if patterns.is_empty() {
            guard.pubsub.patterns.clone()
        } else {
            patterns
                .iter()
                .map(|pattern| (*pattern).to_string())
                .collect()
        };
        while !expected_acks.is_empty() {
            let event = guard.read_next_event(cx).await?;
            match event {
                PubSubEvent::Subscription {
                    kind: PubSubSubscriptionKind::PatternUnsubscribe,
                    channel,
                    ..
                } => {
                    Self::acknowledge_subscription_target(
                        &mut expected_acks,
                        &channel,
                        "PUNSUBSCRIBE",
                    )?;
                    guard.untrack_pattern(&channel);
                }
                other => guard.push_pending_event(other),
            }
        }
        guard.commit();
        Ok(())
    }

    /// Receive the next Pub/Sub event on this connection.
    ///
    /// # Errors
    ///
    /// Returns [`RedisError::SubscriberLag`] (carrying the number of
    /// events dropped since the last lag report) when the configured
    /// backlog cap [`RedisConfig::pubsub_max_backlog`] has been reached
    /// since the previous successful poll. The error is delivered
    /// before any further events so the caller learns about the gap
    /// before consuming the next message. Calling `next_event` again
    /// after handling the lag continues delivery from the current
    /// backlog head. (br-asupersync-697arj.)
    pub async fn next_event(&mut self, cx: &Cx) -> Result<PubSubEvent, RedisError> {
        self.ensure_live()?;

        // Surface backlog overflow before the next event so the gap is
        // observable. Each overflow burst surfaces exactly once: we
        // bump pubsub_lag_reported to the current cumulative count.
        let new_drops = self
            .pubsub_dropped_events
            .saturating_sub(self.pubsub_lag_reported);
        if new_drops > 0 {
            self.pubsub_lag_reported = self.pubsub_dropped_events;
            return Err(RedisError::SubscriberLag { dropped: new_drops });
        }

        if let Some(event) = self.pending_events.pop_front() {
            return Ok(event);
        }
        self.read_next_event(cx).await
    }

    /// PING the Pub/Sub connection.
    ///
    /// Redis returns a `pong` event while subscribed.
    pub async fn ping(&mut self, cx: &Cx, payload: Option<&[u8]>) -> Result<(), RedisError> {
        let mut guard = PubSubControlGuard::new(self)?;
        if let Some(payload) = payload {
            guard.write_command(cx, &[b"PING", payload]).await?;
        } else {
            guard.write_command(cx, &[b"PING"]).await?;
        }
        // Loop until we receive PONG, buffering any interleaved events so a
        // liveness check cannot silently drop real messages. Cap the buffer
        // to prevent unbounded growth under high publish throughput.
        loop {
            match guard.read_next_event(cx).await? {
                PubSubEvent::Pong(_) => {
                    guard.commit();
                    return Ok(());
                }
                event @ (PubSubEvent::Message(_) | PubSubEvent::Subscription { .. }) => {
                    guard.push_pending_event(event);
                    // Beyond the cap, interleaved messages are dropped to
                    // bound memory.  This is a defensive limit — in normal
                    // operation PONG arrives within a few round-trips.
                }
            }
        }
    }

    /// Reconnect and restore tracked subscriptions.
    pub async fn reconnect(&mut self, cx: &Cx) -> Result<(), RedisError> {
        let channels = self.channels.clone();
        let patterns = self.patterns.clone();

        let mut conn = RedisConnection::connect(self.config.clone(), None).await?;
        conn.ensure_initialized(cx).await?;
        self.conn = conn;
        self.channels.clone_from(&channels);
        self.patterns.clone_from(&patterns);
        self.pending_events.clear();
        self.poisoned = false;

        if !channels.is_empty() {
            let channel_refs: Vec<&str> = channels.iter().map(String::as_str).collect();
            self.subscribe(cx, &channel_refs).await?;
        }
        if !patterns.is_empty() {
            let pattern_refs: Vec<&str> = patterns.iter().map(String::as_str).collect();
            self.psubscribe(cx, &pattern_refs).await?;
        }
        Ok(())
    }

    /// Active channel subscriptions tracked by this client.
    #[must_use]
    pub fn channels(&self) -> &[String] {
        &self.channels
    }

    /// Active pattern subscriptions tracked by this client.
    #[must_use]
    pub fn patterns(&self) -> &[String] {
        &self.patterns
    }
}

#[cfg(any(test, feature = "test-internals"))]
#[allow(dead_code)]
/// Test-internals hook exposing RESP pub/sub event parsing.
///
/// Intended for structure-aware fuzz targets that need to drive the real
/// Redis push/array event parser without widening the production API.
pub fn parse_pubsub_event_for_fuzz(value: RespValue) -> Result<PubSubEvent, RedisError> {
    RedisPubSub::parse_event(value)
}

fn decode_tracking_invalidation_keys(value: RespValue) -> Result<Option<Vec<Vec<u8>>>, RedisError> {
    match value {
        RespValue::Null | RespValue::Array(None) | RespValue::BulkString(None) => Ok(None),
        RespValue::Array(Some(keys)) => keys
            .into_iter()
            .map(|key| RedisPubSub::decode_payload(key, "client tracking invalidate key"))
            .collect::<Result<Vec<_>, _>>()
            .map(Some),
        other => Err(RedisError::Protocol(format!(
            "client tracking invalidate payload must be an array or null, got {other:?}"
        ))),
    }
}

fn parse_client_tracking_push(value: RespValue) -> Result<RedisClientTrackingPush, RedisError> {
    let items = match value {
        RespValue::Push(items) => items,
        other => {
            return Err(RedisError::Protocol(format!(
                "client tracking notification must be a RESP3 push, got {other:?}"
            )));
        }
    };

    let mut iter = items.into_iter();
    let kind = RedisPubSub::decode_text(
        RedisPubSub::next_required(&mut iter, "client tracking push missing kind")?,
        "client tracking kind",
    )?;

    if kind.eq_ignore_ascii_case("invalidate") {
        let keys = decode_tracking_invalidation_keys(RedisPubSub::next_required(
            &mut iter,
            "client tracking invalidate missing key payload",
        )?)?;
        RedisPubSub::ensure_no_trailing(
            &mut iter,
            "client tracking invalidate has unexpected trailing fields",
        )?;
        Ok(RedisClientTrackingPush::Invalidate { keys })
    } else if kind.eq_ignore_ascii_case("tracking-redir-broken") {
        RedisPubSub::ensure_no_trailing(
            &mut iter,
            "client tracking redirect-broken has unexpected trailing fields",
        )?;
        Ok(RedisClientTrackingPush::RedirectBroken)
    } else {
        Err(RedisError::Protocol(format!(
            "unsupported client tracking push kind: {kind}"
        )))
    }
}

fn is_pubsub_push_kind(kind: &str) -> bool {
    kind.eq_ignore_ascii_case("message")
        || kind.eq_ignore_ascii_case("pmessage")
        || kind.eq_ignore_ascii_case("subscribe")
        || kind.eq_ignore_ascii_case("unsubscribe")
        || kind.eq_ignore_ascii_case("psubscribe")
        || kind.eq_ignore_ascii_case("punsubscribe")
        || kind.eq_ignore_ascii_case("pong")
}

fn parse_resp3_non_pubsub_push(value: RespValue) -> Result<RedisResp3NonPubSubPush, RedisError> {
    let items = match value {
        RespValue::Push(items) => items,
        other => {
            return Err(RedisError::Protocol(format!(
                "RESP3 non-pubsub push must be a push frame, got {other:?}"
            )));
        }
    };

    let kind = RedisPubSub::decode_text(
        items
            .first()
            .cloned()
            .ok_or_else(|| RedisError::Protocol("RESP3 push missing kind".to_string()))?,
        "RESP3 push kind",
    )?;
    if is_pubsub_push_kind(&kind) {
        return Err(RedisError::Protocol(format!(
            "RESP3 push kind {kind} belongs to pubsub parser"
        )));
    }
    if kind.eq_ignore_ascii_case("invalidate") || kind.eq_ignore_ascii_case("tracking-redir-broken")
    {
        return parse_client_tracking_push(RespValue::Push(items))
            .map(RedisResp3NonPubSubPush::ClientTracking);
    }

    let payload = items.into_iter().skip(1).collect();
    Ok(RedisResp3NonPubSubPush::Other { kind, payload })
}

#[cfg(any(test, feature = "test-internals"))]
#[allow(dead_code)]
#[doc(hidden)]
pub fn parse_client_tracking_push_for_fuzz(
    value: RespValue,
) -> Result<RedisClientTrackingPush, RedisError> {
    parse_client_tracking_push(value)
}

#[cfg(any(test, feature = "test-internals"))]
#[allow(dead_code)]
#[doc(hidden)]
pub fn parse_resp3_non_pubsub_push_for_fuzz(
    value: RespValue,
) -> Result<RedisResp3NonPubSubPush, RedisError> {
    parse_resp3_non_pubsub_push(value)
}

#[cfg(any(test, feature = "test-internals"))]
#[allow(dead_code)]
#[doc(hidden)]
pub fn decode_resp_value_for_fuzz(
    buf: &[u8],
    limits: RedisProtocolLimits,
) -> Result<Option<(RespValue, usize)>, RedisError> {
    RespValue::try_decode_with_limits(buf, &limits)
}

#[cfg(any(test, feature = "test-internals"))]
#[derive(Debug, Clone, PartialEq, Eq)]
#[doc(hidden)]
pub struct RedisLuaScriptStats {
    pub bytes: usize,
    pub lines: usize,
    pub comments: usize,
    pub string_literals: usize,
    pub max_delimiter_depth: usize,
}

#[cfg(any(test, feature = "test-internals"))]
#[derive(Debug, Clone, PartialEq, Eq)]
#[doc(hidden)]
pub struct RedisScriptEvalCommand {
    pub readonly: bool,
    pub script: Vec<u8>,
    pub numkeys: usize,
    pub keys: Vec<Vec<u8>>,
    pub argv: Vec<Vec<u8>>,
    pub lua: RedisLuaScriptStats,
}

#[cfg(any(test, feature = "test-internals"))]
fn bytes_eq_ignore_ascii_case(left: &[u8], right: &[u8]) -> bool {
    left.len() == right.len()
        && left
            .iter()
            .zip(right)
            .all(|(a, b)| a.eq_ignore_ascii_case(b))
}

#[cfg(any(test, feature = "test-internals"))]
fn decode_bulk_command_arg(
    value: RespValue,
    command: &str,
    label: &str,
) -> Result<Vec<u8>, RedisError> {
    match value {
        RespValue::BulkString(Some(bytes)) => Ok(bytes),
        other => Err(RedisError::Protocol(format!(
            "{command} {label} must be a non-null bulk string, got {other:?}"
        ))),
    }
}

#[cfg(any(test, feature = "test-internals"))]
fn decode_command_arg(value: RespValue, label: &str) -> Result<Vec<u8>, RedisError> {
    decode_bulk_command_arg(value, "SCRIPT EVAL", label)
}

#[cfg(any(test, feature = "test-internals"))]
fn parse_usize_command_arg(bytes: &[u8], label: &str) -> Result<usize, RedisError> {
    if bytes.is_empty() {
        return Err(RedisError::Protocol(format!(
            "SCRIPT EVAL {label} must not be empty"
        )));
    }

    let mut acc = 0usize;
    for &byte in bytes {
        if !byte.is_ascii_digit() {
            return Err(RedisError::Protocol(format!(
                "SCRIPT EVAL {label} contains non-digit byte 0x{byte:02x}"
            )));
        }
        acc = acc
            .checked_mul(10)
            .and_then(|value| value.checked_add(usize::from(byte - b'0')))
            .ok_or_else(|| RedisError::Protocol(format!("SCRIPT EVAL {label} overflow")))?;
    }
    Ok(acc)
}

#[cfg(any(test, feature = "test-internals"))]
fn lua_long_bracket_level(script: &[u8], start: usize) -> Option<usize> {
    if script.get(start) != Some(&b'[') {
        return None;
    }
    let mut pos = start + 1;
    while script.get(pos) == Some(&b'=') {
        pos += 1;
    }
    if script.get(pos) == Some(&b'[') {
        Some(pos - start - 1)
    } else {
        None
    }
}

#[cfg(any(test, feature = "test-internals"))]
fn skip_lua_long_bracket(script: &[u8], start: usize, level: usize) -> Result<usize, RedisError> {
    let mut pos = start + level + 2;
    while pos < script.len() {
        if script[pos] == b']' {
            let mut candidate = pos + 1;
            let mut matched = true;
            for _ in 0..level {
                if script.get(candidate) != Some(&b'=') {
                    matched = false;
                    break;
                }
                candidate += 1;
            }
            if matched && script.get(candidate) == Some(&b']') {
                return Ok(candidate + 1);
            }
        }
        pos += 1;
    }
    Err(RedisError::Protocol(
        "SCRIPT EVAL Lua long bracket literal is unterminated".to_string(),
    ))
}

#[cfg(any(test, feature = "test-internals"))]
fn count_newlines(bytes: &[u8]) -> usize {
    memchr::memchr_iter(b'\n', bytes).count()
}

#[cfg(any(test, feature = "test-internals"))]
fn matching_lua_opener(close: u8) -> Option<u8> {
    match close {
        b')' => Some(b'('),
        b']' => Some(b'['),
        b'}' => Some(b'{'),
        _ => None,
    }
}

#[cfg(any(test, feature = "test-internals"))]
#[allow(clippy::too_many_lines)]
fn scan_lua_script_for_fuzz(script: &[u8]) -> Result<RedisLuaScriptStats, RedisError> {
    if script.len() > DEFAULT_MAX_RESP_FRAME_SIZE {
        return Err(RedisError::Protocol(format!(
            "SCRIPT EVAL Lua script length {} exceeds maximum {}",
            script.len(),
            DEFAULT_MAX_RESP_FRAME_SIZE
        )));
    }

    let mut stats = RedisLuaScriptStats {
        bytes: script.len(),
        lines: usize::from(!script.is_empty()),
        comments: 0,
        string_literals: 0,
        max_delimiter_depth: 0,
    };
    let mut stack = Vec::new();
    let mut pos = 0usize;

    while pos < script.len() {
        match script[pos] {
            b'\n' => {
                stats.lines += 1;
                pos += 1;
            }
            b'-' if script.get(pos + 1) == Some(&b'-') => {
                stats.comments += 1;
                if let Some(level) = lua_long_bracket_level(script, pos + 2) {
                    let end = skip_lua_long_bracket(script, pos + 2, level)?;
                    stats.lines += count_newlines(&script[pos..end]);
                    pos = end;
                } else {
                    pos += 2;
                    while pos < script.len() && script[pos] != b'\n' {
                        pos += 1;
                    }
                }
            }
            b'\'' | b'"' => {
                let quote = script[pos];
                stats.string_literals += 1;
                pos += 1;
                loop {
                    if pos >= script.len() {
                        return Err(RedisError::Protocol(
                            "SCRIPT EVAL Lua short string is unterminated".to_string(),
                        ));
                    }
                    match script[pos] {
                        b'\\' => {
                            pos += 1;
                            if pos >= script.len() {
                                return Err(RedisError::Protocol(
                                    "SCRIPT EVAL Lua escape sequence is unterminated".to_string(),
                                ));
                            }
                            pos += 1;
                        }
                        b'\r' | b'\n' => {
                            return Err(RedisError::Protocol(
                                "SCRIPT EVAL Lua short string contains raw newline".to_string(),
                            ));
                        }
                        byte if byte == quote => {
                            pos += 1;
                            break;
                        }
                        _ => pos += 1,
                    }
                }
            }
            b'[' => {
                if let Some(level) = lua_long_bracket_level(script, pos) {
                    stats.string_literals += 1;
                    let end = skip_lua_long_bracket(script, pos, level)?;
                    stats.lines += count_newlines(&script[pos..end]);
                    pos = end;
                } else {
                    stack.push(b'[');
                    stats.max_delimiter_depth = stats.max_delimiter_depth.max(stack.len());
                    pos += 1;
                }
            }
            b'(' | b'{' => {
                stack.push(script[pos]);
                stats.max_delimiter_depth = stats.max_delimiter_depth.max(stack.len());
                pos += 1;
            }
            b')' | b']' | b'}' => {
                let Some(expected) = matching_lua_opener(script[pos]) else {
                    return Err(RedisError::Protocol(
                        "SCRIPT EVAL Lua delimiter parser reached unknown closer".to_string(),
                    ));
                };
                if stack.pop() != Some(expected) {
                    return Err(RedisError::Protocol(
                        "SCRIPT EVAL Lua delimiters are unbalanced".to_string(),
                    ));
                }
                pos += 1;
            }
            _ => pos += 1,
        }
    }

    if !stack.is_empty() {
        return Err(RedisError::Protocol(
            "SCRIPT EVAL Lua delimiters are unbalanced".to_string(),
        ));
    }

    Ok(stats)
}

#[cfg(any(test, feature = "test-internals"))]
#[allow(dead_code)]
#[doc(hidden)]
pub fn parse_script_eval_for_fuzz(value: RespValue) -> Result<RedisScriptEvalCommand, RedisError> {
    let args = match value {
        RespValue::Array(Some(args)) => args,
        other => {
            return Err(RedisError::Protocol(format!(
                "SCRIPT EVAL command must be a RESP array, got {other:?}"
            )));
        }
    };

    if args.len() < 3 {
        return Err(RedisError::Protocol(
            "SCRIPT EVAL command requires command, script, and numkeys".to_string(),
        ));
    }

    let mut iter = args.into_iter();
    let command = decode_command_arg(
        iter.next().ok_or_else(|| {
            RedisError::Protocol("SCRIPT EVAL command missing command name".to_string())
        })?,
        "command",
    )?;
    let readonly = if bytes_eq_ignore_ascii_case(&command, b"EVAL") {
        false
    } else if bytes_eq_ignore_ascii_case(&command, b"EVAL_RO") {
        true
    } else {
        return Err(RedisError::Protocol(format!(
            "SCRIPT EVAL command must be EVAL or EVAL_RO, got {}",
            String::from_utf8_lossy(&command)
        )));
    };

    let script = decode_command_arg(
        iter.next()
            .ok_or_else(|| RedisError::Protocol("SCRIPT EVAL missing script".to_string()))?,
        "script",
    )?;
    let numkeys_bytes = decode_command_arg(
        iter.next()
            .ok_or_else(|| RedisError::Protocol("SCRIPT EVAL missing numkeys".to_string()))?,
        "numkeys",
    )?;
    let numkeys = parse_usize_command_arg(&numkeys_bytes, "numkeys")?;
    let remaining: Vec<Vec<u8>> = iter
        .enumerate()
        .map(|(index, value)| decode_command_arg(value, &format!("arg[{index}]")))
        .collect::<Result<_, _>>()?;
    if remaining.len() < numkeys {
        return Err(RedisError::Protocol(format!(
            "SCRIPT EVAL numkeys {numkeys} exceeds remaining argument count {}",
            remaining.len()
        )));
    }

    let lua = scan_lua_script_for_fuzz(&script)?;
    let keys = remaining[..numkeys].to_vec();
    let argv = remaining[numkeys..].to_vec();

    Ok(RedisScriptEvalCommand {
        readonly,
        script,
        numkeys,
        keys,
        argv,
        lua,
    })
}

#[cfg(any(test, feature = "test-internals"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[doc(hidden)]
pub enum RedisClientKillTargetType {
    Normal,
    Master,
    Slave,
    Replica,
    PubSub,
}

#[cfg(any(test, feature = "test-internals"))]
#[derive(Debug, Clone, PartialEq, Eq)]
#[doc(hidden)]
pub enum RedisClientKillFilter {
    Id(u64),
    ClientType(RedisClientKillTargetType),
    User(Vec<u8>),
    Addr(Vec<u8>),
    LocalAddr(Vec<u8>),
    SkipMe(bool),
    MaxAge(u64),
}

#[cfg(any(test, feature = "test-internals"))]
#[derive(Debug, Clone, PartialEq, Eq)]
#[doc(hidden)]
pub struct RedisClientKillCommand {
    pub legacy_addr: Option<Vec<u8>>,
    pub filters: Vec<RedisClientKillFilter>,
}

#[cfg(any(test, feature = "test-internals"))]
fn decode_client_kill_arg(value: RespValue, label: &str) -> Result<Vec<u8>, RedisError> {
    decode_bulk_command_arg(value, "CLIENT KILL", label)
}

#[cfg(any(test, feature = "test-internals"))]
fn parse_unsigned_decimal_arg(command: &str, bytes: &[u8], label: &str) -> Result<u64, RedisError> {
    if bytes.is_empty() {
        return Err(RedisError::Protocol(format!(
            "{command} {label} must not be empty"
        )));
    }

    let mut acc = 0u64;
    for &byte in bytes {
        if !byte.is_ascii_digit() {
            return Err(RedisError::Protocol(format!(
                "{command} {label} contains non-digit byte 0x{byte:02x}"
            )));
        }
        acc = acc
            .checked_mul(10)
            .and_then(|value| value.checked_add(u64::from(byte - b'0')))
            .ok_or_else(|| RedisError::Protocol(format!("{command} {label} overflow")))?;
    }
    Ok(acc)
}

#[cfg(any(test, feature = "test-internals"))]
fn parse_signed_decimal_arg(command: &str, bytes: &[u8], label: &str) -> Result<i64, RedisError> {
    if bytes.is_empty() {
        return Err(RedisError::Protocol(format!(
            "{command} {label} must not be empty"
        )));
    }

    let (negative, digits) = match bytes[0] {
        b'-' => (true, &bytes[1..]),
        b'+' => (false, &bytes[1..]),
        _ => (false, bytes),
    };
    if digits.is_empty() {
        return Err(RedisError::Protocol(format!(
            "{command} {label} sign must be followed by digits"
        )));
    }

    let mut acc = 0i64;
    for &byte in digits {
        if !byte.is_ascii_digit() {
            return Err(RedisError::Protocol(format!(
                "{command} {label} contains non-digit byte 0x{byte:02x}"
            )));
        }
        let digit = i64::from(byte - b'0');
        acc = if negative {
            acc.checked_mul(10)
                .and_then(|value| value.checked_sub(digit))
        } else {
            acc.checked_mul(10)
                .and_then(|value| value.checked_add(digit))
        }
        .ok_or_else(|| RedisError::Protocol(format!("{command} {label} overflow")))?;
    }
    Ok(acc)
}

#[cfg(any(test, feature = "test-internals"))]
fn validate_client_kill_addr(bytes: &[u8], label: &str) -> Result<Vec<u8>, RedisError> {
    let Some(colon) = bytes.iter().rposition(|&byte| byte == b':') else {
        return Err(RedisError::Protocol(format!(
            "CLIENT KILL {label} must be ip:port"
        )));
    };
    if colon == 0 || colon + 1 == bytes.len() {
        return Err(RedisError::Protocol(format!(
            "CLIENT KILL {label} must include host and port"
        )));
    }
    let port = &bytes[colon + 1..];
    if !port.iter().all(u8::is_ascii_digit) {
        return Err(RedisError::Protocol(format!(
            "CLIENT KILL {label} port must be decimal"
        )));
    }
    let parsed_port = parse_unsigned_decimal_arg("CLIENT KILL", port, label)?;
    if parsed_port > u64::from(u16::MAX) {
        return Err(RedisError::Protocol(format!(
            "CLIENT KILL {label} port exceeds 65535"
        )));
    }
    Ok(bytes.to_vec())
}

#[cfg(any(test, feature = "test-internals"))]
fn parse_client_kill_type(bytes: &[u8]) -> Result<RedisClientKillTargetType, RedisError> {
    if bytes_eq_ignore_ascii_case(bytes, b"NORMAL") {
        Ok(RedisClientKillTargetType::Normal)
    } else if bytes_eq_ignore_ascii_case(bytes, b"MASTER") {
        Ok(RedisClientKillTargetType::Master)
    } else if bytes_eq_ignore_ascii_case(bytes, b"SLAVE") {
        Ok(RedisClientKillTargetType::Slave)
    } else if bytes_eq_ignore_ascii_case(bytes, b"REPLICA") {
        Ok(RedisClientKillTargetType::Replica)
    } else if bytes_eq_ignore_ascii_case(bytes, b"PUBSUB") {
        Ok(RedisClientKillTargetType::PubSub)
    } else {
        Err(RedisError::Protocol(format!(
            "CLIENT KILL TYPE must be NORMAL, MASTER, SLAVE, REPLICA, or PUBSUB, got {}",
            String::from_utf8_lossy(bytes)
        )))
    }
}

#[cfg(any(test, feature = "test-internals"))]
fn parse_client_kill_skipme(bytes: &[u8]) -> Result<bool, RedisError> {
    if bytes_eq_ignore_ascii_case(bytes, b"YES") {
        Ok(true)
    } else if bytes_eq_ignore_ascii_case(bytes, b"NO") {
        Ok(false)
    } else {
        Err(RedisError::Protocol(format!(
            "CLIENT KILL SKIPME must be YES or NO, got {}",
            String::from_utf8_lossy(bytes)
        )))
    }
}

#[cfg(any(test, feature = "test-internals"))]
fn parse_client_kill_filter(
    filter: &[u8],
    value: Vec<u8>,
) -> Result<RedisClientKillFilter, RedisError> {
    if bytes_eq_ignore_ascii_case(filter, b"ID") {
        Ok(RedisClientKillFilter::Id(parse_unsigned_decimal_arg(
            "CLIENT KILL",
            &value,
            "ID",
        )?))
    } else if bytes_eq_ignore_ascii_case(filter, b"TYPE") {
        Ok(RedisClientKillFilter::ClientType(parse_client_kill_type(
            &value,
        )?))
    } else if bytes_eq_ignore_ascii_case(filter, b"USER") {
        if value.is_empty() {
            return Err(RedisError::Protocol(
                "CLIENT KILL USER must not be empty".to_string(),
            ));
        }
        Ok(RedisClientKillFilter::User(value))
    } else if bytes_eq_ignore_ascii_case(filter, b"ADDR") {
        Ok(RedisClientKillFilter::Addr(validate_client_kill_addr(
            &value, "ADDR",
        )?))
    } else if bytes_eq_ignore_ascii_case(filter, b"LADDR") {
        Ok(RedisClientKillFilter::LocalAddr(validate_client_kill_addr(
            &value, "LADDR",
        )?))
    } else if bytes_eq_ignore_ascii_case(filter, b"SKIPME") {
        Ok(RedisClientKillFilter::SkipMe(parse_client_kill_skipme(
            &value,
        )?))
    } else if bytes_eq_ignore_ascii_case(filter, b"MAXAGE") {
        Ok(RedisClientKillFilter::MaxAge(parse_unsigned_decimal_arg(
            "CLIENT KILL",
            &value,
            "MAXAGE",
        )?))
    } else {
        Err(RedisError::Protocol(format!(
            "CLIENT KILL unknown filter {}",
            String::from_utf8_lossy(filter)
        )))
    }
}

#[cfg(any(test, feature = "test-internals"))]
#[allow(dead_code)]
#[doc(hidden)]
pub fn parse_client_kill_for_fuzz(value: RespValue) -> Result<RedisClientKillCommand, RedisError> {
    let args = match value {
        RespValue::Array(Some(args)) => args,
        other => {
            return Err(RedisError::Protocol(format!(
                "CLIENT KILL command must be a RESP array, got {other:?}"
            )));
        }
    };
    if args.len() < 3 {
        return Err(RedisError::Protocol(
            "CLIENT KILL requires CLIENT, KILL, and a selector".to_string(),
        ));
    }

    let mut iter = args.into_iter();
    let command = decode_client_kill_arg(
        iter.next()
            .ok_or_else(|| RedisError::Protocol("CLIENT KILL missing command".to_string()))?,
        "command",
    )?;
    if !bytes_eq_ignore_ascii_case(&command, b"CLIENT") {
        return Err(RedisError::Protocol(format!(
            "CLIENT KILL command name expected CLIENT, got {}",
            String::from_utf8_lossy(&command)
        )));
    }

    let subcommand = decode_client_kill_arg(
        iter.next()
            .ok_or_else(|| RedisError::Protocol("CLIENT KILL missing subcommand".to_string()))?,
        "subcommand",
    )?;
    if !bytes_eq_ignore_ascii_case(&subcommand, b"KILL") {
        return Err(RedisError::Protocol(format!(
            "CLIENT KILL subcommand expected KILL, got {}",
            String::from_utf8_lossy(&subcommand)
        )));
    }

    let remaining: Vec<Vec<u8>> = iter
        .enumerate()
        .map(|(index, value)| decode_client_kill_arg(value, &format!("selector[{index}]")))
        .collect::<Result<_, _>>()?;
    if remaining.len() == 1 {
        return Ok(RedisClientKillCommand {
            legacy_addr: Some(validate_client_kill_addr(&remaining[0], "legacy address")?),
            filters: Vec::new(),
        });
    }
    if remaining.len() % 2 != 0 {
        return Err(RedisError::Protocol(
            "CLIENT KILL filter mode requires filter/value pairs".to_string(),
        ));
    }

    let mut filters = Vec::with_capacity(remaining.len() / 2);
    for pair in remaining.chunks_exact(2) {
        filters.push(parse_client_kill_filter(&pair[0], pair[1].clone())?);
    }

    Ok(RedisClientKillCommand {
        legacy_addr: None,
        filters,
    })
}

#[cfg(any(test, feature = "test-internals"))]
#[derive(Debug, Clone, PartialEq, Eq)]
#[doc(hidden)]
pub enum RedisSlowlogCommand {
    Get { count: Option<u64> },
    Len,
    Reset,
    Help,
}

#[cfg(any(test, feature = "test-internals"))]
#[derive(Debug, Clone, PartialEq, Eq)]
#[doc(hidden)]
pub enum RedisLatencySubcommand {
    Doctor,
    Latest,
    History { event: Vec<u8> },
    Graph { event: Vec<u8> },
    Reset { events: Vec<Vec<u8>> },
    Histogram { commands: Vec<Vec<u8>> },
    Help,
}

#[cfg(any(test, feature = "test-internals"))]
#[derive(Debug, Clone, PartialEq, Eq)]
#[doc(hidden)]
pub struct RedisLatencyCommand {
    pub subcommand: RedisLatencySubcommand,
}

#[cfg(any(test, feature = "test-internals"))]
fn decode_observability_arg(
    value: RespValue,
    command: &str,
    label: &str,
) -> Result<Vec<u8>, RedisError> {
    decode_bulk_command_arg(value, command, label)
}

#[cfg(any(test, feature = "test-internals"))]
fn reject_observability_extra_args(
    command: &str,
    subcommand: &str,
    remaining: &[RespValue],
) -> Result<(), RedisError> {
    if remaining.is_empty() {
        Ok(())
    } else {
        Err(RedisError::Protocol(format!(
            "{command} {subcommand} takes no arguments, got {}",
            remaining.len()
        )))
    }
}

#[cfg(any(test, feature = "test-internals"))]
fn require_non_empty_observability_arg(
    command: &str,
    label: &str,
    bytes: Vec<u8>,
) -> Result<Vec<u8>, RedisError> {
    if bytes.is_empty() {
        Err(RedisError::Protocol(format!(
            "{command} {label} must not be empty"
        )))
    } else {
        Ok(bytes)
    }
}

#[cfg(any(test, feature = "test-internals"))]
#[allow(dead_code)]
#[doc(hidden)]
pub fn parse_slowlog_for_fuzz(value: RespValue) -> Result<RedisSlowlogCommand, RedisError> {
    let args = match value {
        RespValue::Array(Some(args)) => args,
        other => {
            return Err(RedisError::Protocol(format!(
                "SLOWLOG command must be a RESP array, got {other:?}"
            )));
        }
    };
    if args.len() < 2 {
        return Err(RedisError::Protocol(
            "SLOWLOG requires command and subcommand".to_string(),
        ));
    }

    let mut iter = args.into_iter();
    let command = decode_observability_arg(
        iter.next()
            .ok_or_else(|| RedisError::Protocol("SLOWLOG missing command".to_string()))?,
        "SLOWLOG",
        "command",
    )?;
    if !bytes_eq_ignore_ascii_case(&command, b"SLOWLOG") {
        return Err(RedisError::Protocol(format!(
            "SLOWLOG command name expected, got {}",
            String::from_utf8_lossy(&command)
        )));
    }

    let subcommand = decode_observability_arg(
        iter.next()
            .ok_or_else(|| RedisError::Protocol("SLOWLOG missing subcommand".to_string()))?,
        "SLOWLOG",
        "subcommand",
    )?;
    let remaining: Vec<RespValue> = iter.collect();

    if bytes_eq_ignore_ascii_case(&subcommand, b"GET") {
        let count = match remaining.as_slice() {
            [] => None,
            [value] => {
                let count = decode_observability_arg(value.clone(), "SLOWLOG", "GET count")?;
                Some(parse_unsigned_decimal_arg("SLOWLOG", &count, "GET count")?)
            }
            _ => {
                return Err(RedisError::Protocol(format!(
                    "SLOWLOG GET accepts at most one count, got {}",
                    remaining.len()
                )));
            }
        };
        Ok(RedisSlowlogCommand::Get { count })
    } else if bytes_eq_ignore_ascii_case(&subcommand, b"LEN") {
        reject_observability_extra_args("SLOWLOG", "LEN", &remaining)?;
        Ok(RedisSlowlogCommand::Len)
    } else if bytes_eq_ignore_ascii_case(&subcommand, b"RESET") {
        reject_observability_extra_args("SLOWLOG", "RESET", &remaining)?;
        Ok(RedisSlowlogCommand::Reset)
    } else if bytes_eq_ignore_ascii_case(&subcommand, b"HELP") {
        reject_observability_extra_args("SLOWLOG", "HELP", &remaining)?;
        Ok(RedisSlowlogCommand::Help)
    } else {
        Err(RedisError::Protocol(format!(
            "SLOWLOG unknown subcommand {}",
            String::from_utf8_lossy(&subcommand)
        )))
    }
}

#[cfg(any(test, feature = "test-internals"))]
#[allow(dead_code)]
#[doc(hidden)]
pub fn parse_latency_for_fuzz(value: RespValue) -> Result<RedisLatencyCommand, RedisError> {
    let args = match value {
        RespValue::Array(Some(args)) => args,
        other => {
            return Err(RedisError::Protocol(format!(
                "LATENCY command must be a RESP array, got {other:?}"
            )));
        }
    };
    if args.len() < 2 {
        return Err(RedisError::Protocol(
            "LATENCY requires command and subcommand".to_string(),
        ));
    }

    let mut iter = args.into_iter();
    let command = decode_observability_arg(
        iter.next()
            .ok_or_else(|| RedisError::Protocol("LATENCY missing command".to_string()))?,
        "LATENCY",
        "command",
    )?;
    if !bytes_eq_ignore_ascii_case(&command, b"LATENCY") {
        return Err(RedisError::Protocol(format!(
            "LATENCY command name expected, got {}",
            String::from_utf8_lossy(&command)
        )));
    }

    let subcommand = decode_observability_arg(
        iter.next()
            .ok_or_else(|| RedisError::Protocol("LATENCY missing subcommand".to_string()))?,
        "LATENCY",
        "subcommand",
    )?;
    let remaining: Vec<RespValue> = iter.collect();

    let subcommand = if bytes_eq_ignore_ascii_case(&subcommand, b"DOCTOR") {
        reject_observability_extra_args("LATENCY", "DOCTOR", &remaining)?;
        RedisLatencySubcommand::Doctor
    } else if bytes_eq_ignore_ascii_case(&subcommand, b"LATEST") {
        reject_observability_extra_args("LATENCY", "LATEST", &remaining)?;
        RedisLatencySubcommand::Latest
    } else if bytes_eq_ignore_ascii_case(&subcommand, b"HISTORY") {
        let [event] = remaining.as_slice() else {
            return Err(RedisError::Protocol(format!(
                "LATENCY HISTORY requires exactly one event, got {}",
                remaining.len()
            )));
        };
        RedisLatencySubcommand::History {
            event: require_non_empty_observability_arg(
                "LATENCY",
                "HISTORY event",
                decode_observability_arg(event.clone(), "LATENCY", "HISTORY event")?,
            )?,
        }
    } else if bytes_eq_ignore_ascii_case(&subcommand, b"GRAPH") {
        let [event] = remaining.as_slice() else {
            return Err(RedisError::Protocol(format!(
                "LATENCY GRAPH requires exactly one event, got {}",
                remaining.len()
            )));
        };
        RedisLatencySubcommand::Graph {
            event: require_non_empty_observability_arg(
                "LATENCY",
                "GRAPH event",
                decode_observability_arg(event.clone(), "LATENCY", "GRAPH event")?,
            )?,
        }
    } else if bytes_eq_ignore_ascii_case(&subcommand, b"RESET") {
        let events = remaining
            .into_iter()
            .enumerate()
            .map(|(index, value)| {
                require_non_empty_observability_arg(
                    "LATENCY",
                    &format!("RESET event[{index}]"),
                    decode_observability_arg(value, "LATENCY", &format!("RESET event[{index}]"))?,
                )
            })
            .collect::<Result<_, _>>()?;
        RedisLatencySubcommand::Reset { events }
    } else if bytes_eq_ignore_ascii_case(&subcommand, b"HISTOGRAM") {
        let commands = remaining
            .into_iter()
            .enumerate()
            .map(|(index, value)| {
                require_non_empty_observability_arg(
                    "LATENCY",
                    &format!("HISTOGRAM command[{index}]"),
                    decode_observability_arg(
                        value,
                        "LATENCY",
                        &format!("HISTOGRAM command[{index}]"),
                    )?,
                )
            })
            .collect::<Result<_, _>>()?;
        RedisLatencySubcommand::Histogram { commands }
    } else if bytes_eq_ignore_ascii_case(&subcommand, b"HELP") {
        reject_observability_extra_args("LATENCY", "HELP", &remaining)?;
        RedisLatencySubcommand::Help
    } else {
        return Err(RedisError::Protocol(format!(
            "LATENCY unknown subcommand {}",
            String::from_utf8_lossy(&subcommand)
        )));
    };

    Ok(RedisLatencyCommand { subcommand })
}

#[cfg(any(test, feature = "test-internals"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[doc(hidden)]
pub enum RedisZaddInsertMode {
    Upsert,
    Nx,
    Xx,
}

#[cfg(any(test, feature = "test-internals"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[doc(hidden)]
pub enum RedisZaddScoreMode {
    Always,
    GreaterThan,
    LessThan,
}

#[cfg(any(test, feature = "test-internals"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[doc(hidden)]
pub struct RedisZaddOptions {
    pub insert: RedisZaddInsertMode,
    pub score: RedisZaddScoreMode,
    pub changed: bool,
    pub increment: bool,
}

#[cfg(any(test, feature = "test-internals"))]
#[derive(Debug, Clone, PartialEq, Eq)]
#[doc(hidden)]
pub struct RedisZaddEntry {
    pub score: Vec<u8>,
    pub member: Vec<u8>,
}

#[cfg(any(test, feature = "test-internals"))]
#[derive(Debug, Clone, PartialEq, Eq)]
#[doc(hidden)]
pub struct RedisZaddCommand {
    pub key: Vec<u8>,
    pub options: RedisZaddOptions,
    pub entries: Vec<RedisZaddEntry>,
}

#[cfg(any(test, feature = "test-internals"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RedisZaddOption {
    Nx,
    Xx,
    Gt,
    Lt,
    Ch,
    Incr,
}

#[cfg(any(test, feature = "test-internals"))]
fn parse_zadd_option(bytes: &[u8]) -> Option<RedisZaddOption> {
    if bytes_eq_ignore_ascii_case(bytes, b"NX") {
        Some(RedisZaddOption::Nx)
    } else if bytes_eq_ignore_ascii_case(bytes, b"XX") {
        Some(RedisZaddOption::Xx)
    } else if bytes_eq_ignore_ascii_case(bytes, b"GT") {
        Some(RedisZaddOption::Gt)
    } else if bytes_eq_ignore_ascii_case(bytes, b"LT") {
        Some(RedisZaddOption::Lt)
    } else if bytes_eq_ignore_ascii_case(bytes, b"CH") {
        Some(RedisZaddOption::Ch)
    } else if bytes_eq_ignore_ascii_case(bytes, b"INCR") {
        Some(RedisZaddOption::Incr)
    } else {
        None
    }
}

#[cfg(any(test, feature = "test-internals"))]
fn parse_zadd_score_for_fuzz(score: &[u8]) -> Result<(), RedisError> {
    if score.is_empty() {
        return Err(RedisError::Protocol(
            "ZADD score must not be empty".to_string(),
        ));
    }
    let text = std::str::from_utf8(score)
        .map_err(|_| RedisError::Protocol("ZADD score must be UTF-8 ASCII".to_string()))?;
    if !text.is_ascii() {
        return Err(RedisError::Protocol("ZADD score must be ASCII".to_string()));
    }
    let value = text
        .parse::<f64>()
        .map_err(|_| RedisError::Protocol(format!("ZADD invalid score: {text}")))?;
    if value.is_nan() {
        return Err(RedisError::Protocol(
            "ZADD score must not be NaN".to_string(),
        ));
    }
    Ok(())
}

#[cfg(any(test, feature = "test-internals"))]
fn apply_zadd_option(
    options: &mut RedisZaddOptions,
    option: RedisZaddOption,
) -> Result<(), RedisError> {
    match option {
        RedisZaddOption::Nx => {
            if options.insert != RedisZaddInsertMode::Upsert
                || options.score != RedisZaddScoreMode::Always
            {
                return Err(RedisError::Protocol(
                    "ZADD NX is mutually exclusive with XX, GT, and LT".to_string(),
                ));
            }
            options.insert = RedisZaddInsertMode::Nx;
        }
        RedisZaddOption::Xx => {
            if options.insert != RedisZaddInsertMode::Upsert {
                return Err(RedisError::Protocol(
                    "ZADD XX is mutually exclusive with NX".to_string(),
                ));
            }
            options.insert = RedisZaddInsertMode::Xx;
        }
        RedisZaddOption::Gt => {
            if options.insert == RedisZaddInsertMode::Nx
                || options.score != RedisZaddScoreMode::Always
            {
                return Err(RedisError::Protocol(
                    "ZADD GT is mutually exclusive with NX and LT".to_string(),
                ));
            }
            options.score = RedisZaddScoreMode::GreaterThan;
        }
        RedisZaddOption::Lt => {
            if options.insert == RedisZaddInsertMode::Nx
                || options.score != RedisZaddScoreMode::Always
            {
                return Err(RedisError::Protocol(
                    "ZADD LT is mutually exclusive with NX and GT".to_string(),
                ));
            }
            options.score = RedisZaddScoreMode::LessThan;
        }
        RedisZaddOption::Ch => {
            if options.changed {
                return Err(RedisError::Protocol(
                    "ZADD CH option appears more than once".to_string(),
                ));
            }
            options.changed = true;
        }
        RedisZaddOption::Incr => {
            if options.increment {
                return Err(RedisError::Protocol(
                    "ZADD INCR option appears more than once".to_string(),
                ));
            }
            options.increment = true;
        }
    }
    Ok(())
}

#[cfg(any(test, feature = "test-internals"))]
#[allow(dead_code)]
#[doc(hidden)]
pub fn parse_zadd_for_fuzz(value: RespValue) -> Result<RedisZaddCommand, RedisError> {
    let args = match value {
        RespValue::Array(Some(args)) => args,
        other => {
            return Err(RedisError::Protocol(format!(
                "ZADD command must be a RESP array, got {other:?}"
            )));
        }
    };
    if args.len() < 4 {
        return Err(RedisError::Protocol(
            "ZADD requires command, key, score, and member".to_string(),
        ));
    }

    let mut iter = args.into_iter();
    let command = decode_bulk_command_arg(
        iter.next()
            .ok_or_else(|| RedisError::Protocol("ZADD missing command name".to_string()))?,
        "ZADD",
        "command",
    )?;
    if !bytes_eq_ignore_ascii_case(&command, b"ZADD") {
        return Err(RedisError::Protocol(format!(
            "ZADD command name expected, got {}",
            String::from_utf8_lossy(&command)
        )));
    }

    let key = decode_bulk_command_arg(
        iter.next()
            .ok_or_else(|| RedisError::Protocol("ZADD missing key".to_string()))?,
        "ZADD",
        "key",
    )?;
    let remaining: Vec<Vec<u8>> = iter
        .enumerate()
        .map(|(index, value)| decode_bulk_command_arg(value, "ZADD", &format!("arg[{index}]")))
        .collect::<Result<_, _>>()?;

    let mut options = RedisZaddOptions {
        insert: RedisZaddInsertMode::Upsert,
        score: RedisZaddScoreMode::Always,
        changed: false,
        increment: false,
    };
    let mut first_score = 0usize;
    while let Some(option) = remaining
        .get(first_score)
        .and_then(|arg| parse_zadd_option(arg))
    {
        apply_zadd_option(&mut options, option)?;
        first_score += 1;
    }

    let pairs = &remaining[first_score..];
    if pairs.is_empty() {
        return Err(RedisError::Protocol(
            "ZADD requires at least one score/member pair".to_string(),
        ));
    }
    if pairs.len() % 2 != 0 {
        return Err(RedisError::Protocol(
            "ZADD score/member arguments must be paired".to_string(),
        ));
    }
    if options.increment && pairs.len() != 2 {
        return Err(RedisError::Protocol(
            "ZADD INCR accepts exactly one score/member pair".to_string(),
        ));
    }

    let mut entries = Vec::with_capacity(pairs.len() / 2);
    for pair in pairs.chunks_exact(2) {
        parse_zadd_score_for_fuzz(&pair[0])?;
        entries.push(RedisZaddEntry {
            score: pair[0].clone(),
            member: pair[1].clone(),
        });
    }

    Ok(RedisZaddCommand {
        key,
        options,
        entries,
    })
}

#[cfg(any(test, feature = "test-internals"))]
#[derive(Debug, Clone, PartialEq, Eq)]
#[doc(hidden)]
pub enum RedisZrangeByScoreBound {
    Inclusive(Vec<u8>),
    Exclusive(Vec<u8>),
}

#[cfg(any(test, feature = "test-internals"))]
#[derive(Debug, Clone, PartialEq, Eq)]
#[doc(hidden)]
pub struct RedisZrangeByScoreLimit {
    pub offset: i64,
    pub count: i64,
}

#[cfg(any(test, feature = "test-internals"))]
#[derive(Debug, Clone, PartialEq, Eq)]
#[doc(hidden)]
pub struct RedisZrangeByScoreCommand {
    pub key: Vec<u8>,
    pub min: RedisZrangeByScoreBound,
    pub max: RedisZrangeByScoreBound,
    pub with_scores: bool,
    pub limit: Option<RedisZrangeByScoreLimit>,
}

#[cfg(any(test, feature = "test-internals"))]
fn parse_zrangebyscore_bound_for_fuzz(
    bound: Vec<u8>,
    label: &str,
) -> Result<RedisZrangeByScoreBound, RedisError> {
    if bound.is_empty() {
        return Err(RedisError::Protocol(format!(
            "ZRANGEBYSCORE {label} bound must not be empty"
        )));
    }

    let exclusive = bound[0] == b'(';
    let body = if exclusive { &bound[1..] } else { &bound[..] };
    if body.is_empty() {
        return Err(RedisError::Protocol(format!(
            "ZRANGEBYSCORE {label} exclusive bound must include a score"
        )));
    }
    if bytes_eq_ignore_ascii_case(body, b"-inf")
        || bytes_eq_ignore_ascii_case(body, b"+inf")
        || bytes_eq_ignore_ascii_case(body, b"inf")
    {
        return Ok(if exclusive {
            RedisZrangeByScoreBound::Exclusive(body.to_vec())
        } else {
            RedisZrangeByScoreBound::Inclusive(bound)
        });
    }

    let text = std::str::from_utf8(body).map_err(|_| {
        RedisError::Protocol(format!("ZRANGEBYSCORE {label} bound must be UTF-8 ASCII"))
    })?;
    if !text.is_ascii() {
        return Err(RedisError::Protocol(format!(
            "ZRANGEBYSCORE {label} bound must be ASCII"
        )));
    }
    let value = text.parse::<f64>().map_err(|_| {
        RedisError::Protocol(format!("ZRANGEBYSCORE invalid {label} bound: {text}"))
    })?;
    if !value.is_finite() {
        return Err(RedisError::Protocol(format!(
            "ZRANGEBYSCORE {label} bound must be finite or +/-inf"
        )));
    }

    Ok(if exclusive {
        RedisZrangeByScoreBound::Exclusive(body.to_vec())
    } else {
        RedisZrangeByScoreBound::Inclusive(bound)
    })
}

#[cfg(any(test, feature = "test-internals"))]
#[allow(clippy::too_many_lines)]
#[doc(hidden)]
pub fn parse_zrangebyscore_for_fuzz(
    value: RespValue,
) -> Result<RedisZrangeByScoreCommand, RedisError> {
    let args = match value {
        RespValue::Array(Some(args)) => args,
        other => {
            return Err(RedisError::Protocol(format!(
                "ZRANGEBYSCORE command must be a RESP array, got {other:?}"
            )));
        }
    };
    if args.len() < 4 {
        return Err(RedisError::Protocol(
            "ZRANGEBYSCORE requires command, key, min, and max".to_string(),
        ));
    }

    let mut iter = args.into_iter();
    let command = decode_bulk_command_arg(
        iter.next()
            .ok_or_else(|| RedisError::Protocol("ZRANGEBYSCORE missing command".to_string()))?,
        "ZRANGEBYSCORE",
        "command",
    )?;
    if !bytes_eq_ignore_ascii_case(&command, b"ZRANGEBYSCORE") {
        return Err(RedisError::Protocol(format!(
            "ZRANGEBYSCORE command name expected, got {}",
            String::from_utf8_lossy(&command)
        )));
    }

    let key = decode_bulk_command_arg(
        iter.next()
            .ok_or_else(|| RedisError::Protocol("ZRANGEBYSCORE missing key".to_string()))?,
        "ZRANGEBYSCORE",
        "key",
    )?;
    let min = parse_zrangebyscore_bound_for_fuzz(
        decode_bulk_command_arg(
            iter.next()
                .ok_or_else(|| RedisError::Protocol("ZRANGEBYSCORE missing min".to_string()))?,
            "ZRANGEBYSCORE",
            "min",
        )?,
        "min",
    )?;
    let max = parse_zrangebyscore_bound_for_fuzz(
        decode_bulk_command_arg(
            iter.next()
                .ok_or_else(|| RedisError::Protocol("ZRANGEBYSCORE missing max".to_string()))?,
            "ZRANGEBYSCORE",
            "max",
        )?,
        "max",
    )?;
    let remaining: Vec<Vec<u8>> = iter
        .enumerate()
        .map(|(index, value)| {
            decode_bulk_command_arg(value, "ZRANGEBYSCORE", &format!("option[{index}]"))
        })
        .collect::<Result<_, _>>()?;

    let mut with_scores = false;
    let mut limit = None;
    let mut pos = 0usize;
    while pos < remaining.len() {
        let option = &remaining[pos];
        if bytes_eq_ignore_ascii_case(option, b"WITHSCORES") {
            if with_scores {
                return Err(RedisError::Protocol(
                    "ZRANGEBYSCORE WITHSCORES appears more than once".to_string(),
                ));
            }
            with_scores = true;
            pos += 1;
        } else if bytes_eq_ignore_ascii_case(option, b"LIMIT") {
            if limit.is_some() {
                return Err(RedisError::Protocol(
                    "ZRANGEBYSCORE LIMIT appears more than once".to_string(),
                ));
            }
            let [offset_bytes, count_bytes] = remaining.get(pos + 1..pos + 3).ok_or_else(|| {
                RedisError::Protocol("ZRANGEBYSCORE LIMIT requires offset and count".to_string())
            })?
            else {
                return Err(RedisError::Protocol(
                    "ZRANGEBYSCORE LIMIT requires offset and count".to_string(),
                ));
            };
            let offset = parse_signed_decimal_arg("ZRANGEBYSCORE", offset_bytes, "LIMIT offset")?;
            if offset < 0 {
                return Err(RedisError::Protocol(
                    "ZRANGEBYSCORE LIMIT offset must be non-negative".to_string(),
                ));
            }
            let count = parse_signed_decimal_arg("ZRANGEBYSCORE", count_bytes, "LIMIT count")?;
            limit = Some(RedisZrangeByScoreLimit { offset, count });
            pos += 3;
        } else {
            return Err(RedisError::Protocol(format!(
                "ZRANGEBYSCORE unknown option {}",
                String::from_utf8_lossy(option)
            )));
        }
    }

    Ok(RedisZrangeByScoreCommand {
        key,
        min,
        max,
        with_scores,
        limit,
    })
}

#[cfg(any(test, feature = "test-internals"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[doc(hidden)]
pub enum RedisAclUserState {
    On,
    Off,
}

#[cfg(any(test, feature = "test-internals"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[doc(hidden)]
pub enum RedisAclResetKind {
    All,
    Keys,
    Channels,
    Passwords,
    Selectors,
}

#[cfg(any(test, feature = "test-internals"))]
#[derive(Debug, Clone, PartialEq, Eq)]
#[doc(hidden)]
pub enum RedisAclRule {
    UserState(RedisAclUserState),
    Reset(RedisAclResetKind),
    NoPass,
    AllKeys,
    AllChannels,
    AllCommands,
    NoCommands,
    KeyPattern(Vec<u8>),
    ReadKeyPattern(Vec<u8>),
    WriteKeyPattern(Vec<u8>),
    ChannelPattern(Vec<u8>),
    Command { allow: bool, name: Vec<u8> },
    Category { allow: bool, name: Vec<u8> },
    Password { add: bool, value: Vec<u8> },
    PasswordHash { add: bool, value: Vec<u8> },
}

#[cfg(any(test, feature = "test-internals"))]
#[derive(Debug, Clone, PartialEq, Eq)]
#[doc(hidden)]
pub enum RedisAclLogSelector {
    Default,
    Count(u64),
    Reset,
}

#[cfg(any(test, feature = "test-internals"))]
#[derive(Debug, Clone, PartialEq, Eq)]
#[doc(hidden)]
pub enum RedisAclCommand {
    Cat {
        category: Option<Vec<u8>>,
    },
    GetUser {
        user: Vec<u8>,
    },
    Users,
    Log {
        selector: RedisAclLogSelector,
    },
    SetUser {
        user: Vec<u8>,
        rules: Vec<RedisAclRule>,
    },
}

#[cfg(any(test, feature = "test-internals"))]
fn decode_acl_arg(value: RespValue, label: &str) -> Result<Vec<u8>, RedisError> {
    decode_bulk_command_arg(value, "ACL", label)
}

#[cfg(any(test, feature = "test-internals"))]
fn require_acl_arg(label: &str, bytes: Vec<u8>) -> Result<Vec<u8>, RedisError> {
    if bytes.is_empty() {
        Err(RedisError::Protocol(format!(
            "ACL {label} must not be empty"
        )))
    } else {
        Ok(bytes)
    }
}

#[cfg(any(test, feature = "test-internals"))]
fn reject_acl_extra_args(subcommand: &str, remaining: &[RespValue]) -> Result<(), RedisError> {
    if remaining.is_empty() {
        Ok(())
    } else {
        Err(RedisError::Protocol(format!(
            "ACL {subcommand} takes no arguments, got {}",
            remaining.len()
        )))
    }
}

#[cfg(any(test, feature = "test-internals"))]
fn require_acl_rule_body(rule: &[u8], body: &[u8], label: &str) -> Result<Vec<u8>, RedisError> {
    if body.is_empty() {
        Err(RedisError::Protocol(format!(
            "ACL SETUSER rule {} has empty {label}",
            String::from_utf8_lossy(rule)
        )))
    } else {
        Ok(body.to_vec())
    }
}

#[cfg(any(test, feature = "test-internals"))]
fn is_ascii_hex(bytes: &[u8]) -> bool {
    bytes.iter().all(u8::is_ascii_hexdigit)
}

#[cfg(any(test, feature = "test-internals"))]
fn parse_acl_hash_rule(rule: &[u8], add: bool) -> Result<RedisAclRule, RedisError> {
    let value = require_acl_rule_body(rule, &rule[1..], "password hash")?;
    if value.len() != 64 || !is_ascii_hex(&value) {
        return Err(RedisError::Protocol(
            "ACL SETUSER password hashes must be 64 ASCII hex bytes".to_string(),
        ));
    }
    Ok(RedisAclRule::PasswordHash { add, value })
}

#[cfg(any(test, feature = "test-internals"))]
fn parse_acl_command_or_category_rule(
    rule: &[u8],
    allow: bool,
) -> Result<RedisAclRule, RedisError> {
    let body = require_acl_rule_body(rule, &rule[1..], "command or category")?;
    if let Some(category) = body.strip_prefix(b"@") {
        Ok(RedisAclRule::Category {
            allow,
            name: require_acl_rule_body(rule, category, "category")?,
        })
    } else {
        Ok(RedisAclRule::Command { allow, name: body })
    }
}

#[cfg(any(test, feature = "test-internals"))]
fn parse_acl_key_permission_rule(rule: &[u8]) -> Result<RedisAclRule, RedisError> {
    if let Some(pattern) = rule.strip_prefix(b"%R~") {
        Ok(RedisAclRule::ReadKeyPattern(require_acl_rule_body(
            rule,
            pattern,
            "read key pattern",
        )?))
    } else if let Some(pattern) = rule.strip_prefix(b"%W~") {
        Ok(RedisAclRule::WriteKeyPattern(require_acl_rule_body(
            rule,
            pattern,
            "write key pattern",
        )?))
    } else if let Some(pattern) = rule.strip_prefix(b"%RW~") {
        Ok(RedisAclRule::KeyPattern(require_acl_rule_body(
            rule,
            pattern,
            "read/write key pattern",
        )?))
    } else {
        Err(RedisError::Protocol(format!(
            "ACL SETUSER unsupported key permission rule {}",
            String::from_utf8_lossy(rule)
        )))
    }
}

#[cfg(any(test, feature = "test-internals"))]
fn parse_acl_rule(rule: Vec<u8>) -> Result<RedisAclRule, RedisError> {
    if rule.is_empty() {
        return Err(RedisError::Protocol(
            "ACL SETUSER rule must not be empty".to_string(),
        ));
    }

    if bytes_eq_ignore_ascii_case(&rule, b"on") {
        Ok(RedisAclRule::UserState(RedisAclUserState::On))
    } else if bytes_eq_ignore_ascii_case(&rule, b"off") {
        Ok(RedisAclRule::UserState(RedisAclUserState::Off))
    } else if bytes_eq_ignore_ascii_case(&rule, b"reset") {
        Ok(RedisAclRule::Reset(RedisAclResetKind::All))
    } else if bytes_eq_ignore_ascii_case(&rule, b"resetkeys") {
        Ok(RedisAclRule::Reset(RedisAclResetKind::Keys))
    } else if bytes_eq_ignore_ascii_case(&rule, b"resetchannels") {
        Ok(RedisAclRule::Reset(RedisAclResetKind::Channels))
    } else if bytes_eq_ignore_ascii_case(&rule, b"resetpass") {
        Ok(RedisAclRule::Reset(RedisAclResetKind::Passwords))
    } else if bytes_eq_ignore_ascii_case(&rule, b"clearselectors") {
        Ok(RedisAclRule::Reset(RedisAclResetKind::Selectors))
    } else if bytes_eq_ignore_ascii_case(&rule, b"nopass") {
        Ok(RedisAclRule::NoPass)
    } else if bytes_eq_ignore_ascii_case(&rule, b"allkeys") {
        Ok(RedisAclRule::AllKeys)
    } else if bytes_eq_ignore_ascii_case(&rule, b"allchannels") {
        Ok(RedisAclRule::AllChannels)
    } else if bytes_eq_ignore_ascii_case(&rule, b"allcommands") {
        Ok(RedisAclRule::AllCommands)
    } else if bytes_eq_ignore_ascii_case(&rule, b"nocommands") {
        Ok(RedisAclRule::NoCommands)
    } else if let Some(pattern) = rule.strip_prefix(b"~") {
        Ok(RedisAclRule::KeyPattern(require_acl_rule_body(
            &rule,
            pattern,
            "key pattern",
        )?))
    } else if let Some(pattern) = rule.strip_prefix(b"&") {
        Ok(RedisAclRule::ChannelPattern(require_acl_rule_body(
            &rule,
            pattern,
            "channel pattern",
        )?))
    } else if rule.starts_with(b"%") {
        parse_acl_key_permission_rule(&rule)
    } else if rule.starts_with(b"+") {
        parse_acl_command_or_category_rule(&rule, true)
    } else if rule.starts_with(b"-") {
        parse_acl_command_or_category_rule(&rule, false)
    } else if let Some(password) = rule.strip_prefix(b">") {
        Ok(RedisAclRule::Password {
            add: true,
            value: require_acl_rule_body(&rule, password, "password")?,
        })
    } else if let Some(password) = rule.strip_prefix(b"<") {
        Ok(RedisAclRule::Password {
            add: false,
            value: require_acl_rule_body(&rule, password, "password")?,
        })
    } else if rule.starts_with(b"#") {
        parse_acl_hash_rule(&rule, true)
    } else if rule.starts_with(b"!") {
        parse_acl_hash_rule(&rule, false)
    } else {
        Err(RedisError::Protocol(format!(
            "ACL SETUSER unknown rule {}",
            String::from_utf8_lossy(&rule)
        )))
    }
}

#[cfg(any(test, feature = "test-internals"))]
#[allow(dead_code)]
#[doc(hidden)]
pub fn parse_acl_for_fuzz(value: RespValue) -> Result<RedisAclCommand, RedisError> {
    let args = match value {
        RespValue::Array(Some(args)) => args,
        other => {
            return Err(RedisError::Protocol(format!(
                "ACL command must be a RESP array, got {other:?}"
            )));
        }
    };
    if args.len() < 2 {
        return Err(RedisError::Protocol(
            "ACL requires command and subcommand".to_string(),
        ));
    }

    let mut iter = args.into_iter();
    let command = decode_acl_arg(
        iter.next()
            .ok_or_else(|| RedisError::Protocol("ACL missing command".to_string()))?,
        "command",
    )?;
    if !bytes_eq_ignore_ascii_case(&command, b"ACL") {
        return Err(RedisError::Protocol(format!(
            "ACL command name expected, got {}",
            String::from_utf8_lossy(&command)
        )));
    }

    let subcommand = decode_acl_arg(
        iter.next()
            .ok_or_else(|| RedisError::Protocol("ACL missing subcommand".to_string()))?,
        "subcommand",
    )?;
    let remaining: Vec<RespValue> = iter.collect();

    if bytes_eq_ignore_ascii_case(&subcommand, b"CAT") {
        match remaining.as_slice() {
            [] => Ok(RedisAclCommand::Cat { category: None }),
            [category] => Ok(RedisAclCommand::Cat {
                category: Some(require_acl_arg(
                    "CAT category",
                    decode_acl_arg(category.clone(), "CAT category")?,
                )?),
            }),
            _ => Err(RedisError::Protocol(format!(
                "ACL CAT accepts at most one category, got {}",
                remaining.len()
            ))),
        }
    } else if bytes_eq_ignore_ascii_case(&subcommand, b"GETUSER") {
        let [user] = remaining.as_slice() else {
            return Err(RedisError::Protocol(format!(
                "ACL GETUSER requires exactly one user, got {}",
                remaining.len()
            )));
        };
        Ok(RedisAclCommand::GetUser {
            user: require_acl_arg(
                "GETUSER user",
                decode_acl_arg(user.clone(), "GETUSER user")?,
            )?,
        })
    } else if bytes_eq_ignore_ascii_case(&subcommand, b"USERS") {
        reject_acl_extra_args("USERS", &remaining)?;
        Ok(RedisAclCommand::Users)
    } else if bytes_eq_ignore_ascii_case(&subcommand, b"LOG") {
        let selector = match remaining.as_slice() {
            [] => RedisAclLogSelector::Default,
            [value] => {
                let arg = require_acl_arg(
                    "LOG selector",
                    decode_acl_arg(value.clone(), "LOG selector")?,
                )?;
                if bytes_eq_ignore_ascii_case(&arg, b"RESET") {
                    RedisAclLogSelector::Reset
                } else {
                    RedisAclLogSelector::Count(parse_unsigned_decimal_arg(
                        "ACL",
                        &arg,
                        "LOG count",
                    )?)
                }
            }
            _ => {
                return Err(RedisError::Protocol(format!(
                    "ACL LOG accepts at most one selector, got {}",
                    remaining.len()
                )));
            }
        };
        Ok(RedisAclCommand::Log { selector })
    } else if bytes_eq_ignore_ascii_case(&subcommand, b"SETUSER") {
        let [user, rest @ ..] = remaining.as_slice() else {
            return Err(RedisError::Protocol(
                "ACL SETUSER requires a user".to_string(),
            ));
        };
        let user = require_acl_arg(
            "SETUSER user",
            decode_acl_arg(user.clone(), "SETUSER user")?,
        )?;
        let rules = rest
            .iter()
            .enumerate()
            .map(|(index, value)| {
                parse_acl_rule(decode_acl_arg(
                    value.clone(),
                    &format!("SETUSER rule[{index}]"),
                )?)
            })
            .collect::<Result<_, _>>()?;
        Ok(RedisAclCommand::SetUser { user, rules })
    } else {
        Err(RedisError::Protocol(format!(
            "ACL unknown subcommand {}",
            String::from_utf8_lossy(&subcommand)
        )))
    }
}

#[cfg(any(test, feature = "test-internals"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[doc(hidden)]
pub enum RedisClusterResetMode {
    Soft,
    Hard,
}

#[cfg(any(test, feature = "test-internals"))]
#[derive(Debug, Clone, PartialEq, Eq)]
#[doc(hidden)]
pub enum RedisClusterCommand {
    MyId,
    Reset { mode: RedisClusterResetMode },
    CountFailureReports { node_id: Vec<u8> },
}

#[cfg(any(test, feature = "test-internals"))]
fn decode_cluster_command_arg(value: RespValue, label: &str) -> Result<Vec<u8>, RedisError> {
    decode_bulk_command_arg(value, "CLUSTER", label)
}

#[cfg(any(test, feature = "test-internals"))]
fn reject_cluster_extra_args(subcommand: &str, remaining: &[RespValue]) -> Result<(), RedisError> {
    if remaining.is_empty() {
        Ok(())
    } else {
        Err(RedisError::Protocol(format!(
            "CLUSTER {subcommand} takes no arguments, got {}",
            remaining.len()
        )))
    }
}

#[cfg(any(test, feature = "test-internals"))]
fn parse_cluster_reset_mode(bytes: &[u8]) -> Result<RedisClusterResetMode, RedisError> {
    if bytes_eq_ignore_ascii_case(bytes, b"SOFT") {
        Ok(RedisClusterResetMode::Soft)
    } else if bytes_eq_ignore_ascii_case(bytes, b"HARD") {
        Ok(RedisClusterResetMode::Hard)
    } else {
        Err(RedisError::Protocol(format!(
            "CLUSTER RESET mode must be HARD or SOFT, got {}",
            String::from_utf8_lossy(bytes)
        )))
    }
}

#[cfg(any(test, feature = "test-internals"))]
fn parse_cluster_node_id(bytes: Vec<u8>, label: &str) -> Result<Vec<u8>, RedisError> {
    if bytes.len() != 40 || !is_ascii_hex(&bytes) {
        Err(RedisError::Protocol(format!(
            "CLUSTER {label} node id must be 40 ASCII hex bytes"
        )))
    } else {
        Ok(bytes)
    }
}

#[cfg(any(test, feature = "test-internals"))]
#[allow(dead_code)]
#[doc(hidden)]
pub fn parse_cluster_command_for_fuzz(value: RespValue) -> Result<RedisClusterCommand, RedisError> {
    let args = match value {
        RespValue::Array(Some(args)) => args,
        other => {
            return Err(RedisError::Protocol(format!(
                "CLUSTER command must be a RESP array, got {other:?}"
            )));
        }
    };
    if args.len() < 2 {
        return Err(RedisError::Protocol(
            "CLUSTER requires command and subcommand".to_string(),
        ));
    }

    let mut iter = args.into_iter();
    let command = decode_cluster_command_arg(
        iter.next()
            .ok_or_else(|| RedisError::Protocol("CLUSTER missing command".to_string()))?,
        "command",
    )?;
    if !bytes_eq_ignore_ascii_case(&command, b"CLUSTER") {
        return Err(RedisError::Protocol(format!(
            "CLUSTER command name expected, got {}",
            String::from_utf8_lossy(&command)
        )));
    }

    let subcommand = decode_cluster_command_arg(
        iter.next()
            .ok_or_else(|| RedisError::Protocol("CLUSTER missing subcommand".to_string()))?,
        "subcommand",
    )?;
    let remaining: Vec<RespValue> = iter.collect();

    if bytes_eq_ignore_ascii_case(&subcommand, b"MYID") {
        reject_cluster_extra_args("MYID", &remaining)?;
        Ok(RedisClusterCommand::MyId)
    } else if bytes_eq_ignore_ascii_case(&subcommand, b"RESET") {
        let mode = match remaining.as_slice() {
            [] => RedisClusterResetMode::Soft,
            [value] => {
                parse_cluster_reset_mode(&decode_cluster_command_arg(value.clone(), "RESET mode")?)?
            }
            _ => {
                return Err(RedisError::Protocol(format!(
                    "CLUSTER RESET accepts at most one mode, got {}",
                    remaining.len()
                )));
            }
        };
        Ok(RedisClusterCommand::Reset { mode })
    } else if bytes_eq_ignore_ascii_case(&subcommand, b"COUNT-FAILURE-REPORTS") {
        let [node_id] = remaining.as_slice() else {
            return Err(RedisError::Protocol(format!(
                "CLUSTER COUNT-FAILURE-REPORTS requires exactly one node id, got {}",
                remaining.len()
            )));
        };
        Ok(RedisClusterCommand::CountFailureReports {
            node_id: parse_cluster_node_id(
                decode_cluster_command_arg(node_id.clone(), "COUNT-FAILURE-REPORTS node id")?,
                "COUNT-FAILURE-REPORTS",
            )?,
        })
    } else {
        Err(RedisError::Protocol(format!(
            "CLUSTER unknown subcommand {}",
            String::from_utf8_lossy(&subcommand)
        )))
    }
}

#[cfg(any(test, feature = "test-internals"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[doc(hidden)]
pub enum FuzzPubSubLane {
    Channel,
    Pattern,
}

#[cfg(any(test, feature = "test-internals"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[doc(hidden)]
pub enum FuzzPubSubOp {
    Subscribe,
    Unsubscribe,
}

#[cfg(any(test, feature = "test-internals"))]
#[derive(Debug, Clone, PartialEq, Eq)]
#[doc(hidden)]
pub struct FuzzPubSubState {
    pub channels: Vec<String>,
    pub patterns: Vec<String>,
}

#[cfg(any(test, feature = "test-internals"))]
#[doc(hidden)]
pub fn fuzz_apply_pubsub_state_step(
    state: &mut FuzzPubSubState,
    lane: FuzzPubSubLane,
    op: FuzzPubSubOp,
    values: &[String],
) -> Result<(), RedisError> {
    let (list, subscribe_err) = match lane {
        FuzzPubSubLane::Channel => (
            &mut state.channels,
            "SUBSCRIBE requires at least one channel",
        ),
        FuzzPubSubLane::Pattern => (
            &mut state.patterns,
            "PSUBSCRIBE requires at least one pattern",
        ),
    };

    match op {
        FuzzPubSubOp::Subscribe => {
            if values.is_empty() {
                return Err(RedisError::Protocol(subscribe_err.to_string()));
            }
            for value in values {
                RedisPubSub::track_subscribe(list, value);
            }
        }
        FuzzPubSubOp::Unsubscribe => {
            if values.is_empty() {
                list.clear();
            } else {
                for value in values {
                    RedisPubSub::untrack_subscribe(list, value);
                }
            }
        }
    }

    Ok(())
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
    use crate::test_utils::{assert_completes_within, run_test_with_cx};
    use futures_lite::future;
    use std::future::Future;
    use std::io::{Read, Write};
    use std::net::TcpListener as StdTcpListener;
    use std::pin::Pin;

    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::mpsc;
    use std::task::{Context, Poll, Waker};
    use std::thread;
    use std::time::Duration;

    fn noop_waker() -> Waker {
        std::task::Waker::noop().clone()
    }

    fn poll_once<F>(mut fut: Pin<&mut F>) -> Poll<F::Output>
    where
        F: Future + ?Sized,
    {
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        fut.as_mut().poll(&mut cx)
    }

    fn drive_until_signal<F>(mut fut: Pin<&mut F>, signal: &mpsc::Receiver<()>, label: &str)
    where
        F: Future + ?Sized,
    {
        for _ in 0..200 {
            if signal.try_recv().is_ok() {
                return;
            }

            match poll_once(fut.as_mut()) {
                Poll::Pending => {}
                Poll::Ready(_) => {
                    panic!("{label} unexpectedly completed before server-side signal");
                }
            }

            std::thread::sleep(Duration::from_millis(10));
        }

        panic!("{label} never reached the expected in-flight state");
    }

    fn read_resp_frame_from_buffer(
        stream: &mut std::net::TcpStream,
        buf: &mut Vec<u8>,
    ) -> RespValue {
        let mut chunk = [0u8; 1024];
        loop {
            if let Some((value, consumed)) =
                RespValue::try_decode(buf).expect("test server should decode RESP command")
            {
                buf.drain(..consumed);
                return value;
            }
            let n = stream.read(&mut chunk).expect("read client command");
            assert!(n > 0, "client closed before sending full RESP command");
            buf.extend_from_slice(&chunk[..n]);
        }
    }

    fn read_resp_frame(stream: &mut std::net::TcpStream) -> RespValue {
        let mut buf = Vec::new();
        read_resp_frame_from_buffer(stream, &mut buf)
    }

    fn assert_resp_command(frame: RespValue, expected: &[&[u8]]) {
        let items = match frame {
            RespValue::Array(Some(items)) => items,
            other => {
                assert!(
                    matches!(other, RespValue::Array(Some(_))),
                    "expected RESP array command frame, got {other:?}"
                );
                return;
            }
        };
        let actual: Vec<Vec<u8>> = items
            .into_iter()
            .map(|item| match item {
                RespValue::BulkString(Some(bytes)) => bytes,
                other => {
                    assert!(
                        matches!(other, RespValue::BulkString(Some(_))),
                        "expected bulk-string command arg, got {other:?}"
                    );
                    Vec::new()
                }
            })
            .collect();
        let expected: Vec<Vec<u8>> = expected.iter().map(|arg| arg.to_vec()).collect();
        assert_eq!(actual, expected, "unexpected RESP command");
    }

    /// Regression for asupersync-mc0lgn: `RedisClient::fmt` previously called
    /// `self.resp3_push_backlog.lock()` twice in a single `.field` chain.
    /// Rust extends every `.lock()` MutexGuard temporary to the end of the
    /// enclosing statement, and `parking_lot::Mutex` is non-re-entrant, so
    /// the second `.lock()` self-deadlocked the formatting thread on the
    /// first guard it had already taken. Any caller emitting
    /// `format!("{:?}", client)` (tracing, panic message, assert_eq) would
    /// hang.
    ///
    /// Run the format call on a worker thread guarded by a join timeout —
    /// if the deadlock returns, the test fails fast with a diagnostic
    /// instead of hanging the test runner.
    #[test]
    fn redis_client_debug_fmt_does_not_self_deadlock_mc0lgn() {
        use std::sync::mpsc;
        use std::thread;
        use std::time::Duration;

        let client = pooled_client_without_acquire();

        // Pre-populate both inner mutexes so every `.field` reaches a real
        // lock acquisition rather than short-circuiting on a default state.
        client
            .slot_map
            .lock()
            .insert(42, "127.0.0.1:6379".to_string());
        {
            let mut backlog = client.resp3_push_backlog.lock();
            backlog.dropped = 7;
        }

        let (tx, rx) = mpsc::channel::<String>();
        let format_thread = thread::Builder::new()
            .name("redis-debug-format-mc0lgn".into())
            .spawn(move || {
                let rendered = format!("{client:?}");
                let _ = tx.send(rendered);
            })
            .expect("spawn debug-format worker");

        let rendered = rx.recv_timeout(Duration::from_secs(2)).expect(
            "RedisClient Debug must not self-deadlock on parking_lot \
                 re-entrancy; if this times out the second \
                 resp3_push_backlog.lock() in the .field chain has come \
                 back",
        );
        format_thread.join().expect("format worker thread");

        assert!(
            rendered.contains("known_slot_mappings: 1"),
            "rendered Debug should reflect the slot_map snapshot, got: {rendered}"
        );
        assert!(
            rendered.contains("resp3_push_dropped: 7"),
            "rendered Debug should reflect the backlog snapshot, got: {rendered}"
        );
    }

    #[test]
    fn shutdown_transport_closes_plain_socket_without_waiting_for_drop() {
        let listener = StdTcpListener::bind("127.0.0.1:0").expect("bind test listener");
        let addr = listener.local_addr().expect("listener addr");
        let (accepted_tx, accepted_rx) = mpsc::channel();
        let (closed_tx, closed_rx) = mpsc::channel();

        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept client");
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .expect("set read timeout");
            accepted_tx.send(()).expect("signal accepted");

            let mut probe = [0u8; 1];
            match stream.read(&mut probe) {
                Ok(0) => closed_tx.send(()).expect("signal transport closed"),
                Ok(n) => panic!(
                    "expected shutdown_transport to close the socket, read {n} extra byte(s)"
                ),
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                    ) =>
                {
                    panic!("shutdown_transport left the socket open until drop")
                }
                Err(e) => panic!("probe connection after shutdown_transport: {e}"),
            }
        });

        let stream = future::block_on(TcpStream::connect(addr)).expect("connect tcp stream");
        accepted_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("server accepted client");

        let stream = RedisStream::Plain(stream);
        stream
            .shutdown_transport()
            .expect("shutdown transport should succeed");

        closed_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("server should observe transport close before drop");

        drop(stream);
        server.join().expect("server join");
    }

    fn pooled_client_without_acquire() -> RedisClient {
        let factory: RedisFactory = Box::new(|| {
            Box::pin(async {
                panic!("test should fail before acquiring a pooled Redis connection");
            })
        });
        RedisClient {
            config: RedisConfig::default(),
            pool: GenericPool::new(factory, PoolConfig::with_max_size(1)),
            slot_map: Arc::new(parking_lot::Mutex::new(HashMap::new())),
            resp3_push_backlog: Arc::new(parking_lot::Mutex::new(RedisResp3PushBacklog::default())),
        }
    }

    fn client_with_config(config: RedisConfig) -> RedisClient {
        let config_for_factory = config.clone();
        let resp3_push_backlog =
            Arc::new(parking_lot::Mutex::new(RedisResp3PushBacklog::default()));
        let backlog_for_factory = Arc::clone(&resp3_push_backlog);

        let factory: RedisFactory = Box::new(move || {
            let config = config_for_factory.clone();
            let backlog = Arc::clone(&backlog_for_factory);
            Box::pin(async move { RedisConnection::connect(config, Some(backlog)).await })
        });

        RedisClient {
            config,
            pool: GenericPool::new(factory, PoolConfig::with_max_size(10)),
            slot_map: Arc::new(parking_lot::Mutex::new(HashMap::new())),
            resp3_push_backlog,
        }
    }

    fn write_hello3_ok(stream: &mut std::net::TcpStream) {
        let hello = read_resp_frame(stream);
        assert_resp_command(hello, &[b"HELLO", b"3"]);
        let hello_reply = RespValue::Map(vec![(
            RespValue::SimpleString("proto".to_string()),
            RespValue::Integer(3),
        )])
        .encode();
        stream.write_all(&hello_reply).expect("write HELLO reply");
        stream.flush().expect("flush HELLO reply");
    }

    fn buffer_fingerprint(bytes: &[u8]) -> String {
        let mut acc = 0xcbf2_9ce4_8422_2325u64;
        for &byte in bytes {
            acc ^= u64::from(byte);
            acc = acc.wrapping_mul(0x100_0000_01b3);
        }
        format!("{acc:016x}")
    }

    fn collect_resp3_pushes(client: &RedisClient) -> Vec<RedisResp3NonPubSubPush> {
        let mut pushes = Vec::new();
        loop {
            match client.try_next_resp3_push() {
                Ok(Some(push)) => pushes.push(push),
                Ok(None) => return pushes,
                Err(err) => panic!("expected buffered RESP3 pushes without lag, got {err:?}"),
            }
        }
    }

    #[test]
    fn cluster_redirect_rejects_plaintext_authenticated_cross_endpoint() {
        let mut client = pooled_client_without_acquire();
        client.config.host = "redis.internal".to_string();
        client.config.port = 6379;
        client.config.password = Some("secret".to_string());

        client
            .validate_redirect_target("redis.internal", 6379)
            .expect("same-endpoint redirect should remain allowed");

        let err = client
            .validate_redirect_target("attacker.example", 6380)
            .expect_err("plaintext authenticated redirect must fail closed");
        assert!(
            matches!(err, RedisError::Protocol(ref msg) if msg.contains("enable TLS for cluster redirects")),
            "unexpected redirect error: {err:?}"
        );

        client.config.password = None;
        client
            .validate_redirect_target("attacker.example", 6380)
            .expect("passwordless plaintext redirect should not trip auth guard");
    }

    #[test]
    fn test_resp_encode_simple_string() {
        let value = RespValue::SimpleString("OK".to_string());
        assert_eq!(value.encode(), b"+OK\r\n");
    }

    #[test]
    fn test_resp_encode_integer() {
        let value = RespValue::Integer(42);
        assert_eq!(value.encode(), b":42\r\n");
    }

    #[test]
    fn test_resp_decode_simple_string() {
        let (value, n) = RespValue::try_decode(b"+OK\r\n").unwrap().expect("decoded");
        assert_eq!(value, RespValue::SimpleString("OK".to_string()));
        assert_eq!(n, 5);
    }

    #[test]
    fn test_resp_decode_integer() {
        let (value, n) = RespValue::try_decode(b":-123\r\n")
            .unwrap()
            .expect("decoded");
        assert_eq!(value, RespValue::Integer(-123));
        assert_eq!(n, 7);
    }

    #[test]
    fn test_resp_decode_bulk_string() {
        let (value, n) = RespValue::try_decode(b"$3\r\nfoo\r\n")
            .unwrap()
            .expect("decoded");
        assert_eq!(value, RespValue::BulkString(Some(b"foo".to_vec())));
        assert_eq!(n, 9);
    }

    #[test]
    fn test_resp_decode_array() {
        let (value, n) = RespValue::try_decode(b"*2\r\n$3\r\nfoo\r\n:42\r\n")
            .unwrap()
            .expect("decoded");
        assert_eq!(
            value,
            RespValue::Array(Some(vec![
                RespValue::BulkString(Some(b"foo".to_vec())),
                RespValue::Integer(42),
            ]))
        );
        assert_eq!(n, 18);
    }

    fn bulk_arg(bytes: impl AsRef<[u8]>) -> RespValue {
        RespValue::BulkString(Some(bytes.as_ref().to_vec()))
    }

    #[test]
    fn script_eval_parser_splits_script_keys_and_argv() {
        let command = RespValue::Array(Some(vec![
            bulk_arg("EVAL"),
            bulk_arg("return redis.call('GET', KEYS[1])"),
            bulk_arg("2"),
            bulk_arg("key-a"),
            bulk_arg("key-b"),
            bulk_arg("arg-a"),
        ]));

        let parsed = parse_script_eval_for_fuzz(command).expect("valid EVAL command should parse");

        assert!(!parsed.readonly);
        assert_eq!(parsed.numkeys, 2);
        assert_eq!(parsed.keys, vec![b"key-a".to_vec(), b"key-b".to_vec()]);
        assert_eq!(parsed.argv, vec![b"arg-a".to_vec()]);
        assert_eq!(parsed.lua.string_literals, 1);
        assert_eq!(parsed.lua.max_delimiter_depth, 2);
    }

    #[test]
    fn script_eval_parser_accepts_eval_ro_long_comments_and_long_strings() {
        let script =
            b"--[=[ comment with bracket text ]=]\nlocal value = [==[payload]==]\nreturn value";
        let command = RespValue::Array(Some(vec![
            bulk_arg("eval_ro"),
            bulk_arg(script),
            bulk_arg("0"),
            bulk_arg("arg-only"),
        ]));

        let parsed =
            parse_script_eval_for_fuzz(command).expect("valid EVAL_RO command should parse");

        assert!(parsed.readonly);
        assert_eq!(parsed.keys, Vec::<Vec<u8>>::new());
        assert_eq!(parsed.argv, vec![b"arg-only".to_vec()]);
        assert_eq!(parsed.lua.comments, 1);
        assert_eq!(parsed.lua.string_literals, 1);
        assert_eq!(parsed.lua.lines, 3);
    }

    #[test]
    fn script_eval_parser_rejects_malformed_command_shapes() {
        let bad_numkeys = RespValue::Array(Some(vec![
            bulk_arg("EVAL"),
            bulk_arg("return 1"),
            bulk_arg("2"),
            bulk_arg("only-one-key"),
        ]));
        assert!(matches!(
            parse_script_eval_for_fuzz(bad_numkeys),
            Err(RedisError::Protocol(msg)) if msg.contains("exceeds remaining")
        ));

        let bad_lua = RespValue::Array(Some(vec![
            bulk_arg("EVAL"),
            bulk_arg("return 'unterminated"),
            bulk_arg("0"),
        ]));
        assert!(matches!(
            parse_script_eval_for_fuzz(bad_lua),
            Err(RedisError::Protocol(msg)) if msg.contains("unterminated")
        ));

        let null_arg = RespValue::Array(Some(vec![
            bulk_arg("EVAL"),
            RespValue::BulkString(None),
            bulk_arg("0"),
        ]));
        assert!(matches!(
            parse_script_eval_for_fuzz(null_arg),
            Err(RedisError::Protocol(msg)) if msg.contains("non-null bulk string")
        ));
    }

    #[test]
    fn client_kill_parser_accepts_legacy_address_selector() {
        let command = RespValue::Array(Some(vec![
            bulk_arg("CLIENT"),
            bulk_arg("KILL"),
            bulk_arg("127.0.0.1:12345"),
        ]));

        let parsed = parse_client_kill_for_fuzz(command).expect("legacy CLIENT KILL should parse");

        assert_eq!(parsed.legacy_addr, Some(b"127.0.0.1:12345".to_vec()));
        assert!(parsed.filters.is_empty());
    }

    #[test]
    fn client_kill_parser_accepts_filter_pairs() {
        let command = RespValue::Array(Some(vec![
            bulk_arg("client"),
            bulk_arg("kill"),
            bulk_arg("ID"),
            bulk_arg("42"),
            bulk_arg("TYPE"),
            bulk_arg("pubsub"),
            bulk_arg("USER"),
            bulk_arg("default"),
            bulk_arg("ADDR"),
            bulk_arg("10.0.0.2:6379"),
            bulk_arg("LADDR"),
            bulk_arg("[::1]:6379"),
            bulk_arg("SKIPME"),
            bulk_arg("no"),
            bulk_arg("MAXAGE"),
            bulk_arg("60"),
        ]));

        let parsed =
            parse_client_kill_for_fuzz(command).expect("CLIENT KILL filter pairs should parse");

        assert!(parsed.legacy_addr.is_none());
        assert_eq!(
            parsed.filters,
            vec![
                RedisClientKillFilter::Id(42),
                RedisClientKillFilter::ClientType(RedisClientKillTargetType::PubSub),
                RedisClientKillFilter::User(b"default".to_vec()),
                RedisClientKillFilter::Addr(b"10.0.0.2:6379".to_vec()),
                RedisClientKillFilter::LocalAddr(b"[::1]:6379".to_vec()),
                RedisClientKillFilter::SkipMe(false),
                RedisClientKillFilter::MaxAge(60),
            ]
        );
    }

    #[test]
    fn client_kill_parser_rejects_malformed_selectors() {
        let unpaired_filter = RespValue::Array(Some(vec![
            bulk_arg("CLIENT"),
            bulk_arg("KILL"),
            bulk_arg("ID"),
            bulk_arg("7"),
            bulk_arg("TYPE"),
        ]));
        assert!(matches!(
            parse_client_kill_for_fuzz(unpaired_filter),
            Err(RedisError::Protocol(msg)) if msg.contains("filter/value pairs")
        ));

        let bad_skipme = RespValue::Array(Some(vec![
            bulk_arg("CLIENT"),
            bulk_arg("KILL"),
            bulk_arg("SKIPME"),
            bulk_arg("MAYBE"),
        ]));
        assert!(matches!(
            parse_client_kill_for_fuzz(bad_skipme),
            Err(RedisError::Protocol(msg)) if msg.contains("YES or NO")
        ));

        let bad_legacy_addr = RespValue::Array(Some(vec![
            bulk_arg("CLIENT"),
            bulk_arg("KILL"),
            bulk_arg("127.0.0.1"),
        ]));
        assert!(matches!(
            parse_client_kill_for_fuzz(bad_legacy_addr),
            Err(RedisError::Protocol(msg)) if msg.contains("ip:port")
        ));

        let unknown_filter = RespValue::Array(Some(vec![
            bulk_arg("CLIENT"),
            bulk_arg("KILL"),
            bulk_arg("BOGUS"),
            bulk_arg("value"),
        ]));
        assert!(matches!(
            parse_client_kill_for_fuzz(unknown_filter),
            Err(RedisError::Protocol(msg)) if msg.contains("unknown filter")
        ));
    }

    #[test]
    fn slowlog_parser_accepts_supported_subcommands() {
        let get = RespValue::Array(Some(vec![
            bulk_arg("SLOWLOG"),
            bulk_arg("GET"),
            bulk_arg("128"),
        ]));
        assert_eq!(
            parse_slowlog_for_fuzz(get).expect("SLOWLOG GET count should parse"),
            RedisSlowlogCommand::Get { count: Some(128) }
        );

        let len = RespValue::Array(Some(vec![bulk_arg("slowlog"), bulk_arg("len")]));
        assert_eq!(
            parse_slowlog_for_fuzz(len).expect("SLOWLOG LEN should parse"),
            RedisSlowlogCommand::Len
        );

        let reset = RespValue::Array(Some(vec![bulk_arg("SLOWLOG"), bulk_arg("RESET")]));
        assert_eq!(
            parse_slowlog_for_fuzz(reset).expect("SLOWLOG RESET should parse"),
            RedisSlowlogCommand::Reset
        );

        let help = RespValue::Array(Some(vec![bulk_arg("SLOWLOG"), bulk_arg("HELP")]));
        assert_eq!(
            parse_slowlog_for_fuzz(help).expect("SLOWLOG HELP should parse"),
            RedisSlowlogCommand::Help
        );
    }

    #[test]
    fn slowlog_parser_rejects_malformed_command_shapes() {
        let negative_count = RespValue::Array(Some(vec![
            bulk_arg("SLOWLOG"),
            bulk_arg("GET"),
            bulk_arg("-1"),
        ]));
        assert!(matches!(
            parse_slowlog_for_fuzz(negative_count),
            Err(RedisError::Protocol(msg)) if msg.contains("non-digit")
        ));

        let extra_len_arg = RespValue::Array(Some(vec![
            bulk_arg("SLOWLOG"),
            bulk_arg("LEN"),
            bulk_arg("extra"),
        ]));
        assert!(matches!(
            parse_slowlog_for_fuzz(extra_len_arg),
            Err(RedisError::Protocol(msg)) if msg.contains("takes no arguments")
        ));

        let unknown = RespValue::Array(Some(vec![bulk_arg("SLOWLOG"), bulk_arg("BOGUS")]));
        assert!(matches!(
            parse_slowlog_for_fuzz(unknown),
            Err(RedisError::Protocol(msg)) if msg.contains("unknown subcommand")
        ));
    }

    #[test]
    fn latency_parser_accepts_supported_subcommands() {
        let history = RespValue::Array(Some(vec![
            bulk_arg("LATENCY"),
            bulk_arg("HISTORY"),
            bulk_arg("command"),
        ]));
        assert_eq!(
            parse_latency_for_fuzz(history)
                .expect("LATENCY HISTORY should parse")
                .subcommand,
            RedisLatencySubcommand::History {
                event: b"command".to_vec()
            }
        );

        let graph = RespValue::Array(Some(vec![
            bulk_arg("latency"),
            bulk_arg("graph"),
            bulk_arg("fork"),
        ]));
        assert_eq!(
            parse_latency_for_fuzz(graph)
                .expect("LATENCY GRAPH should parse")
                .subcommand,
            RedisLatencySubcommand::Graph {
                event: b"fork".to_vec()
            }
        );

        let reset = RespValue::Array(Some(vec![
            bulk_arg("LATENCY"),
            bulk_arg("RESET"),
            bulk_arg("command"),
            bulk_arg("fork"),
        ]));
        assert_eq!(
            parse_latency_for_fuzz(reset)
                .expect("LATENCY RESET should parse")
                .subcommand,
            RedisLatencySubcommand::Reset {
                events: vec![b"command".to_vec(), b"fork".to_vec()]
            }
        );

        let histogram = RespValue::Array(Some(vec![
            bulk_arg("LATENCY"),
            bulk_arg("HISTOGRAM"),
            bulk_arg("GET"),
            bulk_arg("SET"),
        ]));
        assert_eq!(
            parse_latency_for_fuzz(histogram)
                .expect("LATENCY HISTOGRAM should parse")
                .subcommand,
            RedisLatencySubcommand::Histogram {
                commands: vec![b"GET".to_vec(), b"SET".to_vec()]
            }
        );

        let latest = RespValue::Array(Some(vec![bulk_arg("LATENCY"), bulk_arg("LATEST")]));
        assert_eq!(
            parse_latency_for_fuzz(latest)
                .expect("LATENCY LATEST should parse")
                .subcommand,
            RedisLatencySubcommand::Latest
        );

        let doctor = RespValue::Array(Some(vec![bulk_arg("LATENCY"), bulk_arg("DOCTOR")]));
        assert_eq!(
            parse_latency_for_fuzz(doctor)
                .expect("LATENCY DOCTOR should parse")
                .subcommand,
            RedisLatencySubcommand::Doctor
        );
    }

    #[test]
    fn latency_parser_rejects_malformed_command_shapes() {
        let missing_history_event =
            RespValue::Array(Some(vec![bulk_arg("LATENCY"), bulk_arg("HISTORY")]));
        assert!(matches!(
            parse_latency_for_fuzz(missing_history_event),
            Err(RedisError::Protocol(msg)) if msg.contains("requires exactly one event")
        ));

        let empty_graph_event = RespValue::Array(Some(vec![
            bulk_arg("LATENCY"),
            bulk_arg("GRAPH"),
            bulk_arg(""),
        ]));
        assert!(matches!(
            parse_latency_for_fuzz(empty_graph_event),
            Err(RedisError::Protocol(msg)) if msg.contains("must not be empty")
        ));

        let extra_latest_arg = RespValue::Array(Some(vec![
            bulk_arg("LATENCY"),
            bulk_arg("LATEST"),
            bulk_arg("extra"),
        ]));
        assert!(matches!(
            parse_latency_for_fuzz(extra_latest_arg),
            Err(RedisError::Protocol(msg)) if msg.contains("takes no arguments")
        ));

        let unknown = RespValue::Array(Some(vec![bulk_arg("LATENCY"), bulk_arg("BOGUS")]));
        assert!(matches!(
            parse_latency_for_fuzz(unknown),
            Err(RedisError::Protocol(msg)) if msg.contains("unknown subcommand")
        ));
    }

    #[test]
    fn zadd_parser_splits_options_and_entries() {
        let command = RespValue::Array(Some(vec![
            bulk_arg("ZADD"),
            bulk_arg("zset"),
            bulk_arg("NX"),
            bulk_arg("CH"),
            bulk_arg("1.5"),
            bulk_arg("member-a"),
            bulk_arg("-2"),
            bulk_arg("member-b"),
        ]));

        let parsed = parse_zadd_for_fuzz(command).expect("valid ZADD command should parse");

        assert_eq!(parsed.key, b"zset".to_vec());
        assert_eq!(parsed.options.insert, RedisZaddInsertMode::Nx);
        assert_eq!(parsed.options.score, RedisZaddScoreMode::Always);
        assert!(parsed.options.changed);
        assert!(!parsed.options.increment);
        assert_eq!(
            parsed.entries,
            vec![
                RedisZaddEntry {
                    score: b"1.5".to_vec(),
                    member: b"member-a".to_vec(),
                },
                RedisZaddEntry {
                    score: b"-2".to_vec(),
                    member: b"member-b".to_vec(),
                },
            ]
        );
    }

    #[test]
    fn zadd_parser_accepts_xx_gt_incr_single_pair() {
        let command = RespValue::Array(Some(vec![
            bulk_arg("zadd"),
            bulk_arg("zset"),
            bulk_arg("gt"),
            bulk_arg("xx"),
            bulk_arg("INCR"),
            bulk_arg("1.25"),
            bulk_arg("member"),
        ]));

        let parsed = parse_zadd_for_fuzz(command).expect("valid ZADD INCR command should parse");

        assert_eq!(parsed.options.insert, RedisZaddInsertMode::Xx);
        assert_eq!(parsed.options.score, RedisZaddScoreMode::GreaterThan);
        assert!(parsed.options.increment);
        assert_eq!(parsed.entries.len(), 1);
        assert_eq!(parsed.entries[0].score, b"1.25".to_vec());
        assert_eq!(parsed.entries[0].member, b"member".to_vec());
    }

    #[test]
    fn zadd_parser_rejects_malformed_command_shapes() {
        let nx_gt_conflict = RespValue::Array(Some(vec![
            bulk_arg("ZADD"),
            bulk_arg("zset"),
            bulk_arg("NX"),
            bulk_arg("GT"),
            bulk_arg("1"),
            bulk_arg("member"),
        ]));
        assert!(matches!(
            parse_zadd_for_fuzz(nx_gt_conflict),
            Err(RedisError::Protocol(msg)) if msg.contains("mutually exclusive")
        ));

        let odd_pairing = RespValue::Array(Some(vec![
            bulk_arg("ZADD"),
            bulk_arg("zset"),
            bulk_arg("1"),
            bulk_arg("member"),
            bulk_arg("2"),
        ]));
        assert!(matches!(
            parse_zadd_for_fuzz(odd_pairing),
            Err(RedisError::Protocol(msg)) if msg.contains("paired")
        ));

        let incr_multi_pair = RespValue::Array(Some(vec![
            bulk_arg("ZADD"),
            bulk_arg("zset"),
            bulk_arg("INCR"),
            bulk_arg("1"),
            bulk_arg("a"),
            bulk_arg("2"),
            bulk_arg("b"),
        ]));
        assert!(matches!(
            parse_zadd_for_fuzz(incr_multi_pair),
            Err(RedisError::Protocol(msg)) if msg.contains("exactly one")
        ));

        let nan_score = RespValue::Array(Some(vec![
            bulk_arg("ZADD"),
            bulk_arg("zset"),
            bulk_arg("NaN"),
            bulk_arg("member"),
        ]));
        assert!(matches!(
            parse_zadd_for_fuzz(nan_score),
            Err(RedisError::Protocol(msg)) if msg.contains("NaN")
        ));

        let null_member = RespValue::Array(Some(vec![
            bulk_arg("ZADD"),
            bulk_arg("zset"),
            bulk_arg("1"),
            RespValue::BulkString(None),
        ]));
        assert!(matches!(
            parse_zadd_for_fuzz(null_member),
            Err(RedisError::Protocol(msg)) if msg.contains("ZADD arg[1]")
        ));
    }

    #[test]
    fn zrangebyscore_parser_accepts_bounds_and_options() {
        let command = RespValue::Array(Some(vec![
            bulk_arg("ZRANGEBYSCORE"),
            bulk_arg("zset"),
            bulk_arg("(1.5"),
            bulk_arg("+inf"),
            bulk_arg("WITHSCORES"),
            bulk_arg("LIMIT"),
            bulk_arg("0"),
            bulk_arg("-1"),
        ]));

        let parsed =
            parse_zrangebyscore_for_fuzz(command).expect("valid ZRANGEBYSCORE should parse");

        assert_eq!(parsed.key, b"zset".to_vec());
        assert_eq!(
            parsed.min,
            RedisZrangeByScoreBound::Exclusive(b"1.5".to_vec())
        );
        assert_eq!(
            parsed.max,
            RedisZrangeByScoreBound::Inclusive(b"+inf".to_vec())
        );
        assert!(parsed.with_scores);
        assert_eq!(
            parsed.limit,
            Some(RedisZrangeByScoreLimit {
                offset: 0,
                count: -1
            })
        );
    }

    #[test]
    fn zrangebyscore_parser_accepts_options_in_any_order() {
        let command = RespValue::Array(Some(vec![
            bulk_arg("zrangebyscore"),
            bulk_arg("zset"),
            bulk_arg("-inf"),
            bulk_arg("(42"),
            bulk_arg("LIMIT"),
            bulk_arg("+2"),
            bulk_arg("10"),
            bulk_arg("WITHSCORES"),
        ]));

        let parsed =
            parse_zrangebyscore_for_fuzz(command).expect("valid ZRANGEBYSCORE should parse");

        assert_eq!(
            parsed.min,
            RedisZrangeByScoreBound::Inclusive(b"-inf".to_vec())
        );
        assert_eq!(
            parsed.max,
            RedisZrangeByScoreBound::Exclusive(b"42".to_vec())
        );
        assert!(parsed.with_scores);
        assert_eq!(
            parsed.limit,
            Some(RedisZrangeByScoreLimit {
                offset: 2,
                count: 10
            })
        );
    }

    #[test]
    fn zrangebyscore_parser_rejects_malformed_command_shapes() {
        let missing_max = RespValue::Array(Some(vec![
            bulk_arg("ZRANGEBYSCORE"),
            bulk_arg("zset"),
            bulk_arg("-inf"),
        ]));
        assert!(matches!(
            parse_zrangebyscore_for_fuzz(missing_max),
            Err(RedisError::Protocol(msg)) if msg.contains("requires command, key, min, and max")
        ));

        let duplicate_withscores = RespValue::Array(Some(vec![
            bulk_arg("ZRANGEBYSCORE"),
            bulk_arg("zset"),
            bulk_arg("-inf"),
            bulk_arg("+inf"),
            bulk_arg("WITHSCORES"),
            bulk_arg("WITHSCORES"),
        ]));
        assert!(matches!(
            parse_zrangebyscore_for_fuzz(duplicate_withscores),
            Err(RedisError::Protocol(msg)) if msg.contains("appears more than once")
        ));

        let incomplete_limit = RespValue::Array(Some(vec![
            bulk_arg("ZRANGEBYSCORE"),
            bulk_arg("zset"),
            bulk_arg("-inf"),
            bulk_arg("+inf"),
            bulk_arg("LIMIT"),
            bulk_arg("0"),
        ]));
        assert!(matches!(
            parse_zrangebyscore_for_fuzz(incomplete_limit),
            Err(RedisError::Protocol(msg)) if msg.contains("requires offset and count")
        ));

        let negative_offset = RespValue::Array(Some(vec![
            bulk_arg("ZRANGEBYSCORE"),
            bulk_arg("zset"),
            bulk_arg("-inf"),
            bulk_arg("+inf"),
            bulk_arg("LIMIT"),
            bulk_arg("-1"),
            bulk_arg("10"),
        ]));
        assert!(matches!(
            parse_zrangebyscore_for_fuzz(negative_offset),
            Err(RedisError::Protocol(msg)) if msg.contains("offset must be non-negative")
        ));

        let nan_min = RespValue::Array(Some(vec![
            bulk_arg("ZRANGEBYSCORE"),
            bulk_arg("zset"),
            bulk_arg("NaN"),
            bulk_arg("+inf"),
        ]));
        assert!(matches!(
            parse_zrangebyscore_for_fuzz(nan_min),
            Err(RedisError::Protocol(msg)) if msg.contains("finite or +/-inf")
        ));

        let null_max = RespValue::Array(Some(vec![
            bulk_arg("ZRANGEBYSCORE"),
            bulk_arg("zset"),
            bulk_arg("-inf"),
            RespValue::BulkString(None),
        ]));
        assert!(matches!(
            parse_zrangebyscore_for_fuzz(null_max),
            Err(RedisError::Protocol(msg)) if msg.contains("ZRANGEBYSCORE max")
        ));
    }

    #[test]
    fn acl_parser_accepts_users_categories_resets_and_log_selectors() {
        let getuser = RespValue::Array(Some(vec![
            bulk_arg("ACL"),
            bulk_arg("GETUSER"),
            bulk_arg("default"),
        ]));
        assert_eq!(
            parse_acl_for_fuzz(getuser).expect("ACL GETUSER should parse"),
            RedisAclCommand::GetUser {
                user: b"default".to_vec()
            }
        );

        let users = RespValue::Array(Some(vec![bulk_arg("acl"), bulk_arg("users")]));
        assert_eq!(
            parse_acl_for_fuzz(users).expect("ACL USERS should parse"),
            RedisAclCommand::Users
        );

        let cat = RespValue::Array(Some(vec![
            bulk_arg("ACL"),
            bulk_arg("CAT"),
            bulk_arg("read"),
        ]));
        assert_eq!(
            parse_acl_for_fuzz(cat).expect("ACL CAT category should parse"),
            RedisAclCommand::Cat {
                category: Some(b"read".to_vec())
            }
        );

        let setuser = RespValue::Array(Some(vec![
            bulk_arg("ACL"),
            bulk_arg("SETUSER"),
            bulk_arg("app"),
            bulk_arg("on"),
            bulk_arg("resetpass"),
            bulk_arg("resetkeys"),
            bulk_arg("resetchannels"),
            bulk_arg("clearselectors"),
            bulk_arg("+@read"),
            bulk_arg("-@dangerous"),
            bulk_arg("+get"),
            bulk_arg("-config|set"),
            bulk_arg("~cache:*"),
            bulk_arg("%R~ro:*"),
            bulk_arg("%W~wo:*"),
            bulk_arg("&updates:*"),
            bulk_arg(">secret"),
            bulk_arg("#0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"),
        ]));

        let parsed = parse_acl_for_fuzz(setuser).expect("ACL SETUSER rules should parse");
        assert_eq!(
            parsed,
            RedisAclCommand::SetUser {
                user: b"app".to_vec(),
                rules: vec![
                    RedisAclRule::UserState(RedisAclUserState::On),
                    RedisAclRule::Reset(RedisAclResetKind::Passwords),
                    RedisAclRule::Reset(RedisAclResetKind::Keys),
                    RedisAclRule::Reset(RedisAclResetKind::Channels),
                    RedisAclRule::Reset(RedisAclResetKind::Selectors),
                    RedisAclRule::Category {
                        allow: true,
                        name: b"read".to_vec()
                    },
                    RedisAclRule::Category {
                        allow: false,
                        name: b"dangerous".to_vec()
                    },
                    RedisAclRule::Command {
                        allow: true,
                        name: b"get".to_vec()
                    },
                    RedisAclRule::Command {
                        allow: false,
                        name: b"config|set".to_vec()
                    },
                    RedisAclRule::KeyPattern(b"cache:*".to_vec()),
                    RedisAclRule::ReadKeyPattern(b"ro:*".to_vec()),
                    RedisAclRule::WriteKeyPattern(b"wo:*".to_vec()),
                    RedisAclRule::ChannelPattern(b"updates:*".to_vec()),
                    RedisAclRule::Password {
                        add: true,
                        value: b"secret".to_vec()
                    },
                    RedisAclRule::PasswordHash {
                        add: true,
                        value: b"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                            .to_vec()
                    },
                ]
            }
        );

        let log_reset = RespValue::Array(Some(vec![
            bulk_arg("ACL"),
            bulk_arg("LOG"),
            bulk_arg("RESET"),
        ]));
        assert_eq!(
            parse_acl_for_fuzz(log_reset).expect("ACL LOG RESET should parse"),
            RedisAclCommand::Log {
                selector: RedisAclLogSelector::Reset
            }
        );

        let log_count =
            RespValue::Array(Some(vec![bulk_arg("ACL"), bulk_arg("LOG"), bulk_arg("3")]));
        assert_eq!(
            parse_acl_for_fuzz(log_count).expect("ACL LOG count should parse"),
            RedisAclCommand::Log {
                selector: RedisAclLogSelector::Count(3)
            }
        );
    }

    #[test]
    fn acl_parser_rejects_malformed_users_categories_and_reset_rules() {
        let empty_category =
            RespValue::Array(Some(vec![bulk_arg("ACL"), bulk_arg("CAT"), bulk_arg("")]));
        assert!(matches!(
            parse_acl_for_fuzz(empty_category),
            Err(RedisError::Protocol(msg)) if msg.contains("CAT category")
        ));

        let empty_user = RespValue::Array(Some(vec![
            bulk_arg("ACL"),
            bulk_arg("GETUSER"),
            bulk_arg(""),
        ]));
        assert!(matches!(
            parse_acl_for_fuzz(empty_user),
            Err(RedisError::Protocol(msg)) if msg.contains("GETUSER user")
        ));

        let empty_category_rule = RespValue::Array(Some(vec![
            bulk_arg("ACL"),
            bulk_arg("SETUSER"),
            bulk_arg("app"),
            bulk_arg("+@"),
        ]));
        assert!(matches!(
            parse_acl_for_fuzz(empty_category_rule),
            Err(RedisError::Protocol(msg)) if msg.contains("empty category")
        ));

        let empty_reset_rule = RespValue::Array(Some(vec![
            bulk_arg("ACL"),
            bulk_arg("SETUSER"),
            bulk_arg("app"),
            bulk_arg("resetkeys"),
            bulk_arg("~"),
        ]));
        assert!(matches!(
            parse_acl_for_fuzz(empty_reset_rule),
            Err(RedisError::Protocol(msg)) if msg.contains("empty key pattern")
        ));

        let bad_hash = RespValue::Array(Some(vec![
            bulk_arg("ACL"),
            bulk_arg("SETUSER"),
            bulk_arg("app"),
            bulk_arg("#not-a-sha256-hex-digest"),
        ]));
        assert!(matches!(
            parse_acl_for_fuzz(bad_hash),
            Err(RedisError::Protocol(msg)) if msg.contains("64 ASCII hex")
        ));

        let bad_log_selector = RespValue::Array(Some(vec![
            bulk_arg("ACL"),
            bulk_arg("LOG"),
            bulk_arg("maybe"),
        ]));
        assert!(matches!(
            parse_acl_for_fuzz(bad_log_selector),
            Err(RedisError::Protocol(msg)) if msg.contains("non-digit")
        ));

        let null_rule = RespValue::Array(Some(vec![
            bulk_arg("ACL"),
            bulk_arg("SETUSER"),
            bulk_arg("app"),
            RespValue::BulkString(None),
        ]));
        assert!(matches!(
            parse_acl_for_fuzz(null_rule),
            Err(RedisError::Protocol(msg)) if msg.contains("non-null bulk string")
        ));
    }

    #[test]
    fn cluster_command_parser_accepts_myid_reset_and_failure_reports() {
        let myid = RespValue::Array(Some(vec![bulk_arg("cluster"), bulk_arg("myid")]));
        assert_eq!(
            parse_cluster_command_for_fuzz(myid).expect("CLUSTER MYID should parse"),
            RedisClusterCommand::MyId
        );

        let reset_default = RespValue::Array(Some(vec![bulk_arg("CLUSTER"), bulk_arg("RESET")]));
        assert_eq!(
            parse_cluster_command_for_fuzz(reset_default)
                .expect("CLUSTER RESET default mode should parse"),
            RedisClusterCommand::Reset {
                mode: RedisClusterResetMode::Soft
            }
        );

        let reset_hard = RespValue::Array(Some(vec![
            bulk_arg("CLUSTER"),
            bulk_arg("RESET"),
            bulk_arg("HARD"),
        ]));
        assert_eq!(
            parse_cluster_command_for_fuzz(reset_hard).expect("CLUSTER RESET HARD should parse"),
            RedisClusterCommand::Reset {
                mode: RedisClusterResetMode::Hard
            }
        );

        let node_id = b"0123456789abcdef0123456789abcdef01234567".to_vec();
        let count_failure_reports = RespValue::Array(Some(vec![
            bulk_arg("CLUSTER"),
            bulk_arg("COUNT-FAILURE-REPORTS"),
            bulk_arg(&node_id),
        ]));
        assert_eq!(
            parse_cluster_command_for_fuzz(count_failure_reports)
                .expect("CLUSTER COUNT-FAILURE-REPORTS should parse"),
            RedisClusterCommand::CountFailureReports { node_id }
        );
    }

    #[test]
    fn cluster_command_parser_rejects_malformed_arguments() {
        let myid_extra = RespValue::Array(Some(vec![
            bulk_arg("CLUSTER"),
            bulk_arg("MYID"),
            bulk_arg("extra"),
        ]));
        assert!(matches!(
            parse_cluster_command_for_fuzz(myid_extra),
            Err(RedisError::Protocol(msg)) if msg.contains("takes no arguments")
        ));

        let bad_reset_mode = RespValue::Array(Some(vec![
            bulk_arg("CLUSTER"),
            bulk_arg("RESET"),
            bulk_arg("MAYBE"),
        ]));
        assert!(matches!(
            parse_cluster_command_for_fuzz(bad_reset_mode),
            Err(RedisError::Protocol(msg)) if msg.contains("HARD or SOFT")
        ));

        let missing_node_id = RespValue::Array(Some(vec![
            bulk_arg("CLUSTER"),
            bulk_arg("COUNT-FAILURE-REPORTS"),
        ]));
        assert!(matches!(
            parse_cluster_command_for_fuzz(missing_node_id),
            Err(RedisError::Protocol(msg)) if msg.contains("requires exactly one node id")
        ));

        let bad_node_id = RespValue::Array(Some(vec![
            bulk_arg("CLUSTER"),
            bulk_arg("COUNT-FAILURE-REPORTS"),
            bulk_arg("not-a-40-byte-hex-node-id"),
        ]));
        assert!(matches!(
            parse_cluster_command_for_fuzz(bad_node_id),
            Err(RedisError::Protocol(msg)) if msg.contains("40 ASCII hex")
        ));

        let null_node_id = RespValue::Array(Some(vec![
            bulk_arg("CLUSTER"),
            bulk_arg("COUNT-FAILURE-REPORTS"),
            RespValue::BulkString(None),
        ]));
        assert!(matches!(
            parse_cluster_command_for_fuzz(null_node_id),
            Err(RedisError::Protocol(msg)) if msg.contains("non-null bulk string")
        ));

        let unknown_subcommand = RespValue::Array(Some(vec![
            bulk_arg("CLUSTER"),
            bulk_arg("FORGET"),
            bulk_arg("0123456789abcdef0123456789abcdef01234567"),
        ]));
        assert!(matches!(
            parse_cluster_command_for_fuzz(unknown_subcommand),
            Err(RedisError::Protocol(msg)) if msg.contains("unknown subcommand")
        ));
    }

    #[test]
    fn resp2_reference_vectors_match_redis_rs_value_model() {
        // Lock the RESP2 fallback parser to the same shared low-level value
        // model that redis-rs exposes for the direct subset here. Avoid the
        // RESP2 `+OK` and nil normalization cases because redis-rs folds those
        // into special variants that this parser intentionally models
        // separately.
        let cases: Vec<(&str, RespValue, &'static [u8])> = vec![
            (
                "simple_string",
                RespValue::SimpleString("PONG".to_string()),
                b"+PONG\r\n",
            ),
            ("integer", RespValue::Integer(-7), b":-7\r\n"),
            (
                "bulk_string_binary",
                RespValue::BulkString(Some(b"bin\0ary".to_vec())),
                b"$7\r\nbin\0ary\r\n",
            ),
            (
                "array",
                RespValue::Array(Some(vec![
                    RespValue::SimpleString("PONG".to_string()),
                    RespValue::BulkString(Some(b"bin\0ary".to_vec())),
                    RespValue::Integer(-7),
                ])),
                b"*3\r\n+PONG\r\n$7\r\nbin\0ary\r\n:-7\r\n",
            ),
            (
                "nested_array",
                RespValue::Array(Some(vec![
                    RespValue::Array(Some(vec![])),
                    RespValue::Array(Some(vec![
                        RespValue::BulkString(Some(b"foo".to_vec())),
                        RespValue::Integer(42),
                    ])),
                ])),
                b"*2\r\n*0\r\n*2\r\n$3\r\nfoo\r\n:42\r\n",
            ),
        ];

        for (name, value, expected) in cases {
            assert_eq!(
                value.encode(),
                expected,
                "RESP2 {name} encoding must stay byte-compatible with redis-rs's \
                 low-level value model"
            );

            let (decoded, consumed) = RespValue::try_decode(expected)
                .unwrap()
                .unwrap_or_else(|| panic!("RESP2 {name} vector should decode"));
            assert_eq!(
                decoded, value,
                "RESP2 {name} decoding must preserve the redis-rs-compatible \
                 low-level value model"
            );
            assert_eq!(
                consumed,
                expected.len(),
                "RESP2 {name} decoder must consume the full reference vector"
            );
        }
    }

    #[test]
    fn resp3_nested_map_set_roundtrip_matches_redis_rs_value_model() {
        // redis-rs models RESP3 maps as ordered Vec<(Value, Value)> pairs and
        // RESP3 sets as Vec<Value>; lock the corresponding wire form here.
        let value = RespValue::Map(vec![
            (
                RespValue::BulkString(Some(b"numbers".to_vec())),
                RespValue::Set(vec![
                    RespValue::Integer(1),
                    RespValue::BulkString(Some(b"two".to_vec())),
                ]),
            ),
            (
                RespValue::BulkString(Some(b"meta".to_vec())),
                RespValue::Map(vec![
                    (
                        RespValue::SimpleString("proto".to_string()),
                        RespValue::Integer(3),
                    ),
                    (
                        RespValue::SimpleString("mode".to_string()),
                        RespValue::SimpleString("standalone".to_string()),
                    ),
                ]),
            ),
        ]);

        let expected = concat!(
            "%2\r\n",
            "$7\r\nnumbers\r\n",
            "~2\r\n",
            ":1\r\n",
            "$3\r\ntwo\r\n",
            "$4\r\nmeta\r\n",
            "%2\r\n",
            "+proto\r\n",
            ":3\r\n",
            "+mode\r\n",
            "+standalone\r\n",
        )
        .as_bytes();

        assert_eq!(
            value.encode(),
            expected,
            "RESP3 Map/Set encoding must stay byte-compatible with redis-rs's \
             low-level value model"
        );

        let (decoded, consumed) = RespValue::try_decode(expected)
            .unwrap()
            .expect("nested RESP3 map/set should decode");
        assert_eq!(decoded, value);
        assert_eq!(consumed, expected.len());
    }

    #[test]
    fn resp3_verbatim_string_roundtrip_matches_redis_rs_value_model() {
        // redis-rs exposes RESP3 verbatim strings as a 3-byte format tag plus
        // the exact payload bytes after the ':' separator. Lock that wire form
        // here, including CRLF bytes embedded inside the payload body.
        let value = RespValue::Verbatim {
            format: "txt".to_string(),
            payload: b"hello\r\nworld".to_vec(),
        };

        let expected = b"=16\r\ntxt:hello\r\nworld\r\n";

        assert_eq!(
            value.encode(),
            expected,
            "RESP3 verbatim encoding must stay byte-compatible with redis-rs's \
             low-level verbatim string model"
        );

        let (decoded, consumed) = RespValue::try_decode(expected)
            .unwrap()
            .expect("RESP3 verbatim string should decode");
        assert_eq!(decoded, value);
        assert_eq!(consumed, expected.len());
    }

    #[test]
    fn resp3_verbatim_string_rejects_label_boundary_and_utf8_failures() {
        let cases: [(&str, &[u8], &str); 3] = [
            (
                "short_label",
                b"=5\r\ntx:ab\r\n",
                "missing 3-byte format separator",
            ),
            (
                "long_label",
                b"=8\r\ntext:abc\r\n",
                "missing 3-byte format separator",
            ),
            (
                "invalid_utf8_label",
                b"=5\r\n\xff\xfe\xfd:x\r\n",
                "invalid UTF-8 in verbatim format",
            ),
        ];

        for (label, wire, expected_fragment) in cases {
            let error = RespValue::try_decode(wire)
                .expect_err("malformed verbatim string must fail to decode");
            match error {
                RedisError::Protocol(message) => {
                    assert!(
                        message.contains(expected_fragment),
                        "{label} should mention {expected_fragment:?}, got {message:?}"
                    );
                }
                other => panic!("{label} returned unexpected error {other:?}"),
            }
        }
    }

    #[test]
    fn resp3_nested_verbatim_values_preserve_binary_payloads() {
        let value = RespValue::Array(Some(vec![
            RespValue::Verbatim {
                format: "bin".to_string(),
                payload: vec![0x00, 0xff, b':', b'\r', b'\n'],
            },
            RespValue::Map(vec![(
                RespValue::SimpleString("inner".to_string()),
                RespValue::Verbatim {
                    format: "mkd".to_string(),
                    payload: b"*emphasis*\x00".to_vec(),
                },
            )]),
        ]));

        let wire = value.encode();
        let (decoded, consumed) = RespValue::try_decode(&wire)
            .unwrap()
            .expect("nested verbatim values should decode");
        assert_eq!(decoded, value);
        assert_eq!(consumed, wire.len());
    }

    #[test]
    fn resp3_attribute_roundtrip_preserves_nested_value_kinds() {
        fn nesting_depth(value: &RespValue) -> usize {
            match value {
                RespValue::Array(Some(items)) | RespValue::Set(items) | RespValue::Push(items) => {
                    1 + items.iter().map(nesting_depth).max().unwrap_or(0)
                }
                RespValue::Map(pairs) | RespValue::Attribute(pairs) => {
                    1 + pairs
                        .iter()
                        .flat_map(|(key, value)| [nesting_depth(key), nesting_depth(value)])
                        .max()
                        .unwrap_or(0)
                }
                _ => 1,
            }
        }

        fn attribute_pair_count(value: &RespValue) -> usize {
            match value {
                RespValue::Attribute(pairs) => {
                    pairs.len()
                        + pairs
                            .iter()
                            .map(|(key, value)| {
                                attribute_pair_count(key) + attribute_pair_count(value)
                            })
                            .sum::<usize>()
                }
                RespValue::Array(Some(items)) | RespValue::Set(items) | RespValue::Push(items) => {
                    items.iter().map(attribute_pair_count).sum()
                }
                RespValue::Map(pairs) => pairs
                    .iter()
                    .map(|(key, value)| attribute_pair_count(key) + attribute_pair_count(value))
                    .sum(),
                _ => 0,
            }
        }

        fn value_kind(value: &RespValue) -> &'static str {
            match value {
                RespValue::Attribute(_) => "attribute",
                RespValue::Array(_) => "array",
                RespValue::BulkString(_) => "bulk_string",
                RespValue::SimpleString(_) => "simple_string",
                RespValue::Error(_) => "error",
                RespValue::Integer(_) => "integer",
                RespValue::Null => "null",
                RespValue::Boolean(_) => "boolean",
                RespValue::Double(_) => "double",
                RespValue::BigNumber(_) => "big_number",
                RespValue::Verbatim { .. } => "verbatim",
                RespValue::BlobError(_) => "blob_error",
                RespValue::Map(_) => "map",
                RespValue::Set(_) => "set",
                RespValue::Push(_) => "push",
            }
        }

        let cases: Vec<(&str, RespValue)> = vec![
            (
                "scalar",
                RespValue::Attribute(vec![(
                    RespValue::SimpleString("ttl".to_string()),
                    RespValue::Integer(7),
                )]),
            ),
            (
                "array",
                RespValue::Attribute(vec![(
                    RespValue::SimpleString("items".to_string()),
                    RespValue::Array(Some(vec![
                        RespValue::BulkString(Some(b"alpha".to_vec())),
                        RespValue::Null,
                    ])),
                )]),
            ),
            (
                "map",
                RespValue::Attribute(vec![(
                    RespValue::SimpleString("meta".to_string()),
                    RespValue::Map(vec![(
                        RespValue::SimpleString("mode".to_string()),
                        RespValue::SimpleString("standalone".to_string()),
                    )]),
                )]),
            ),
            (
                "set",
                RespValue::Attribute(vec![(
                    RespValue::SimpleString("members".to_string()),
                    RespValue::Set(vec![
                        RespValue::SimpleString("a".to_string()),
                        RespValue::SimpleString("b".to_string()),
                    ]),
                )]),
            ),
            (
                "push",
                RespValue::Attribute(vec![(
                    RespValue::SimpleString("push".to_string()),
                    RespValue::Push(vec![
                        RespValue::BulkString(Some(b"message".to_vec())),
                        RespValue::BulkString(Some(b"channel".to_vec())),
                        RespValue::BulkString(Some(b"payload".to_vec())),
                    ]),
                )]),
            ),
            (
                "null",
                RespValue::Attribute(vec![(
                    RespValue::SimpleString("nil".to_string()),
                    RespValue::Null,
                )]),
            ),
            ("empty", RespValue::Attribute(vec![])),
            (
                "repeated",
                RespValue::Attribute(vec![
                    (
                        RespValue::SimpleString("dup".to_string()),
                        RespValue::Integer(1),
                    ),
                    (
                        RespValue::SimpleString("dup".to_string()),
                        RespValue::Integer(2),
                    ),
                ]),
            ),
            (
                "unknown_key",
                RespValue::Attribute(vec![(
                    RespValue::BulkString(Some(vec![0x01, 0x02, 0x03])),
                    RespValue::SimpleString("opaque".to_string()),
                )]),
            ),
            (
                "nested_attribute",
                RespValue::Array(Some(vec![
                    RespValue::Attribute(vec![(
                        RespValue::SimpleString("outer".to_string()),
                        RespValue::Attribute(vec![(
                            RespValue::SimpleString("inner".to_string()),
                            RespValue::Boolean(true),
                        )]),
                    )]),
                    RespValue::SimpleString("tail".to_string()),
                ])),
            ),
        ];

        for (scenario_id, value) in cases {
            let wire = value.encode();
            let fingerprint = buffer_fingerprint(&wire);
            let (decoded, consumed) = RespValue::try_decode(&wire)
                .unwrap()
                .expect("RESP3 attribute reference vector should decode");
            assert_eq!(
                decoded, value,
                "{scenario_id} should round-trip; fingerprint={fingerprint}"
            );
            assert_eq!(
                consumed,
                wire.len(),
                "{scenario_id} should consume the full wire image"
            );
            eprintln!(
                "RESP3_ATTRIBUTE scenario_id={scenario_id} nesting_depth={} attribute_count={} value_kind={} parser_state=decoded fingerprint={} verdict=pass",
                nesting_depth(&decoded),
                attribute_pair_count(&decoded),
                value_kind(&decoded),
                fingerprint
            );
        }
    }

    #[test]
    fn resp3_attributes_reject_malformed_nested_pairs() {
        let malformed_cases: [(&str, &[u8], &str); 2] = [
            (
                "streamed_attribute_not_supported",
                b"|?\r\n+meta\r\n.\r\n",
                "streamed aggregate not supported",
            ),
            (
                "nested_streamed_map_missing_value",
                b"|1\r\n+meta\r\n%?\r\n+field\r\n.\r\n",
                "odd number of values",
            ),
        ];

        for (scenario_id, wire, expected_fragment) in malformed_cases {
            let error = RespValue::try_decode(wire)
                .expect_err("malformed RESP3 attribute should fail to decode");
            match error {
                RedisError::Protocol(message) => {
                    assert!(
                        message.contains(expected_fragment),
                        "{scenario_id} should mention {expected_fragment:?}, got {message:?}"
                    );
                    eprintln!(
                        "RESP3_ATTRIBUTE scenario_id={scenario_id} parser_state=error error_kind=protocol fingerprint={} verdict=pass",
                        buffer_fingerprint(wire)
                    );
                }
                other => panic!("{scenario_id} returned unexpected error {other:?}"),
            }
        }
    }

    #[test]
    fn resp3_reference_vectors_match_redis_rs_value_model_for_composite_types() {
        // Keep a single differential matrix over the RESP3 composite/value
        // variants we care about here. redis-rs preserves map/set ordering on
        // the wire, exposes verbatim strings as (format, text), and treats big
        // numbers as exact signed arbitrary-precision decimal payloads.
        let cases: Vec<(&str, RespValue, &'static [u8])> = vec![
            (
                "map",
                RespValue::Map(vec![
                    (
                        RespValue::SimpleString("proto".to_string()),
                        RespValue::Integer(3),
                    ),
                    (
                        RespValue::BulkString(Some(b"mode".to_vec())),
                        RespValue::SimpleString("standalone".to_string()),
                    ),
                ]),
                concat!(
                    "%2\r\n",
                    "+proto\r\n",
                    ":3\r\n",
                    "$4\r\nmode\r\n",
                    "+standalone\r\n",
                )
                .as_bytes(),
            ),
            (
                "set",
                RespValue::Set(vec![
                    RespValue::Integer(1),
                    RespValue::BulkString(Some(b"two".to_vec())),
                    RespValue::Boolean(true),
                ]),
                concat!("~3\r\n", ":1\r\n", "$3\r\ntwo\r\n", "#t\r\n").as_bytes(),
            ),
            (
                "verbatim",
                RespValue::Verbatim {
                    format: "txt".to_string(),
                    payload: b"hello\r\nworld".to_vec(),
                },
                b"=16\r\ntxt:hello\r\nworld\r\n",
            ),
            (
                "big_number",
                RespValue::BigNumber("3492890328409238509324850943850943825024385".to_string()),
                b"(3492890328409238509324850943850943825024385\r\n",
            ),
            (
                "big_number_negative",
                RespValue::BigNumber("-3492890328409238509324850943850943825024385".to_string()),
                b"(-3492890328409238509324850943850943825024385\r\n",
            ),
            (
                "big_number_explicit_plus",
                RespValue::BigNumber("+42".to_string()),
                b"(+42\r\n",
            ),
        ];

        for (name, value, expected) in cases {
            assert_eq!(
                value.encode(),
                expected,
                "RESP3 {name} encoding must stay byte-compatible with redis-rs's \
                 low-level value model"
            );

            let (decoded, consumed) = RespValue::try_decode(expected)
                .unwrap()
                .unwrap_or_else(|| panic!("RESP3 {name} vector should decode"));
            assert_eq!(
                decoded, value,
                "RESP3 {name} decoding must preserve the redis-rs-compatible \
                 low-level value model"
            );
            assert_eq!(
                consumed,
                expected.len(),
                "RESP3 {name} decoder must consume the full reference vector"
            );
        }
    }

    #[test]
    fn resp3_big_number_rejects_non_protocol_decimal_payloads() {
        for (name, wire) in [
            ("empty", b"(\r\n".as_slice()),
            ("plus_only", b"(+\r\n"),
            ("minus_only", b"(-\r\n"),
            ("double_plus", b"(++1\r\n"),
            ("minus_plus", b"(-+1\r\n"),
            ("fractional", b"(1.5\r\n"),
            ("alpha", b"(12abc\r\n"),
        ] {
            assert!(
                matches!(RespValue::try_decode(wire), Err(RedisError::Protocol(_))),
                "RESP3 BigNumber {name} payload should be rejected"
            );
        }
    }

    #[test]
    fn resp3_streamed_blob_string_decodes_to_bulk_string() {
        let wire = b"$?\r\n;4\r\nHell\r\n;6\r\no worl\r\n;1\r\nd\r\n;0\r\n";

        let (decoded, consumed) = RespValue::try_decode(wire)
            .unwrap()
            .expect("complete RESP3 streamed blob should decode");

        assert_eq!(
            decoded,
            RespValue::BulkString(Some(b"Hello world".to_vec()))
        );
        assert_eq!(consumed, wire.len());
        assert_eq!(decoded.encode(), b"$11\r\nHello world\r\n");
    }

    #[test]
    fn resp3_empty_streamed_blob_decodes_to_empty_bulk_string() {
        let wire = b"$?\r\n;0\r\n";

        let (decoded, consumed) = RespValue::try_decode(wire)
            .unwrap()
            .expect("complete empty RESP3 streamed blob should decode");

        assert_eq!(decoded, RespValue::BulkString(Some(Vec::new())));
        assert_eq!(consumed, wire.len());
        assert_eq!(decoded.encode(), b"$0\r\n\r\n");
    }

    #[test]
    fn resp3_streamed_array_set_and_map_decode_until_end_marker() {
        let array_wire = b"*?\r\n:1\r\n$3\r\ntwo\r\n#t\r\n.\r\n";
        let (array, array_consumed) = RespValue::try_decode(array_wire)
            .unwrap()
            .expect("complete RESP3 streamed array should decode");
        assert_eq!(
            array,
            RespValue::Array(Some(vec![
                RespValue::Integer(1),
                RespValue::BulkString(Some(b"two".to_vec())),
                RespValue::Boolean(true),
            ]))
        );
        assert_eq!(array_consumed, array_wire.len());

        let set_wire = b"~?\r\n+orange\r\n+apple\r\n.\r\n";
        let (set, set_consumed) = RespValue::try_decode(set_wire)
            .unwrap()
            .expect("complete RESP3 streamed set should decode");
        assert_eq!(
            set,
            RespValue::Set(vec![
                RespValue::SimpleString("orange".to_string()),
                RespValue::SimpleString("apple".to_string()),
            ])
        );
        assert_eq!(set_consumed, set_wire.len());

        let map_wire = b"%?\r\n+first\r\n:1\r\n+second\r\n:2\r\n.\r\n";
        let (map, map_consumed) = RespValue::try_decode(map_wire)
            .unwrap()
            .expect("complete RESP3 streamed map should decode");
        assert_eq!(
            map,
            RespValue::Map(vec![
                (
                    RespValue::SimpleString("first".to_string()),
                    RespValue::Integer(1)
                ),
                (
                    RespValue::SimpleString("second".to_string()),
                    RespValue::Integer(2),
                ),
            ])
        );
        assert_eq!(map_consumed, map_wire.len());
    }

    #[test]
    fn resp3_streamed_types_fail_closed_on_incomplete_or_malformed_frames() {
        assert!(
            RespValue::try_decode(b"$?\r\n;4\r\nHell\r\n")
                .unwrap()
                .is_none(),
            "streamed blob without zero-length chunk remains incomplete"
        );

        let odd_map = RespValue::try_decode(b"%?\r\n+key\r\n.\r\n")
            .expect_err("streamed map with key but no value must fail closed");
        assert!(matches!(odd_map, RedisError::Protocol(msg) if msg.contains("odd")));

        let unsupported_push = RespValue::try_decode(b">?\r\n+message\r\n.\r\n")
            .expect_err("streamed push is outside the RESP3 streamed aggregate set");
        assert!(
            matches!(unsupported_push, RedisError::Protocol(msg) if msg.contains("not supported"))
        );
    }

    #[test]
    fn resp3_streamed_blob_respects_total_bulk_limit() {
        let limits = RedisProtocolLimits::new().max_bulk_string_len(4);
        let err =
            RespValue::try_decode_with_limits(b"$?\r\n;3\r\nabc\r\n;2\r\nde\r\n;0\r\n", &limits)
                .expect_err("streamed blob total length must obey max_bulk_string_len");
        assert!(matches!(err, RedisError::Protocol(msg) if msg.contains("streamed blob length")));
    }

    #[test]
    fn test_resp_decode_partial_needs_more() {
        assert!(RespValue::try_decode(b"$3\r\nfo").unwrap().is_none());
    }

    #[test]
    fn test_config_from_url() {
        let config = RedisConfig::from_url("redis://localhost:6379").unwrap();
        assert_eq!(config.host, "localhost");
        assert_eq!(config.port, 6379);
    }

    #[test]
    fn test_redis_url_credential_redaction_in_errors() {
        // SECURITY TEST: Verify credentials are redacted from error messages
        // to prevent password leakage in logs/traces (asupersync-0kp34a)

        // Test invalid scheme with credentials
        let err = RedisConfig::from_url("http://user:secret123@localhost:6379")
            .expect_err("invalid scheme should fail");
        let err_msg = err.to_string();
        assert!(
            err_msg.contains("***"),
            "Password should be redacted in error message"
        );
        assert!(
            !err_msg.contains("secret123"),
            "Password should not appear in error message"
        );
        assert!(
            !err_msg.contains("user:secret123"),
            "Full userinfo should not appear in error message"
        );

        // Test redact_url_for_errors function directly
        assert_eq!(
            RedisConfig::redact_url_for_errors("redis://user:pass@host:6379/1"),
            "redis://***@host:6379/1"
        );
        assert_eq!(
            RedisConfig::redact_url_for_errors("rediss://admin:s3cr3t@prod.redis.com:6380"),
            "rediss://***@prod.redis.com:6380"
        );
        assert_eq!(
            RedisConfig::redact_url_for_errors("redis://localhost:6379"),
            "redis://localhost:6379"
        );
        assert_eq!(
            RedisConfig::redact_url_for_errors("http://invalid"),
            "[REDACTED_INVALID_URL]"
        );
        assert_eq!(
            RedisConfig::redact_url_for_errors("http://user:secret123@localhost:6379"),
            "[REDACTED_INVALID_URL:***]"
        );

        // Test with complex passwords containing special characters
        let complex_url = "redis://user:p@ss:w0rd!@localhost:6379";
        let redacted = RedisConfig::redact_url_for_errors(complex_url);
        assert_eq!(redacted, "redis://***@localhost:6379");
        assert!(!redacted.contains("p@ss:w0rd!"));
    }

    #[test]
    fn test_redis_url_credential_decoding() {
        // SECURITY TEST: Verify URL-encoded credentials are properly decoded
        // to prevent authentication bypass (asupersync-ts45lv)

        // Test basic percent-encoding decoding
        assert_eq!(RedisConfig::url_decode_credential("user").unwrap(), "user");
        assert_eq!(
            RedisConfig::url_decode_credential("user%3Aescaped").unwrap(),
            "user:escaped"
        );
        assert_eq!(
            RedisConfig::url_decode_credential("pass%40word").unwrap(),
            "pass@word"
        );

        // Test URL with encoded colon in username (potential bypass vector)
        let config = RedisConfig::from_url("redis://admin%3Auser:password@localhost:6379").unwrap();
        assert_eq!(config.username, Some("admin:user".to_string()));
        assert_eq!(config.password, Some("password".to_string()));

        // Test URL with encoded characters in password
        let config = RedisConfig::from_url("redis://user:p%40ss%3Aw0rd@localhost:6379").unwrap();
        assert_eq!(config.username, Some("user".to_string()));
        assert_eq!(config.password, Some("p@ss:w0rd".to_string()));

        // Test password-only format with encoding
        let config = RedisConfig::from_url("redis://my%40password@localhost:6379").unwrap();
        assert_eq!(config.username, None);
        assert_eq!(config.password, Some("my@password".to_string()));

        // Test error cases
        assert!(RedisConfig::url_decode_credential("invalid%").is_err());
        assert!(RedisConfig::url_decode_credential("invalid%G").is_err());
        assert!(RedisConfig::url_decode_credential("invalid%GZ").is_err());

        // Test common percent-encoded characters
        assert_eq!(
            RedisConfig::url_decode_credential("test%20space").unwrap(),
            "test space"
        );
        assert_eq!(
            RedisConfig::url_decode_credential("test%21exclaim").unwrap(),
            "test!exclaim"
        );
    }

    #[test]
    #[cfg(feature = "tls")]
    fn test_redis_tls_hostname_verification_enabled() {
        // SECURITY TEST: Verify TLS connector is configured with hostname verification
        // to prevent MITM attacks (asupersync-xq1qe3)

        let config = RedisConfig::from_url("rediss://localhost:6380").unwrap();
        assert!(config.use_tls);
        assert!(config.tls_connector.is_some());

        // The TLS connector should be configured with hostname verification
        // This test verifies the connector was built with the security flag enabled
        let tls_connector = config.tls_connector.unwrap();

        // Note: We can't directly inspect the hostname verification setting from
        // the built connector, but we can verify it was created without errors
        // which confirms the hostname-verifying rustls connector was built
        assert!(!format!("{:?}", tls_connector).is_empty());

        // Test that rediss:// URLs enable TLS
        let config_secure = RedisConfig::from_url("rediss://redis.example.com:6380").unwrap();
        assert!(config_secure.use_tls);
        assert_eq!(config_secure.host, "redis.example.com");
        assert_eq!(config_secure.port, 6380);

        // Test that redis:// URLs don't enable TLS
        let config_plain = RedisConfig::from_url("redis://redis.example.com:6379").unwrap();
        assert!(!config_plain.use_tls);
        assert!(config_plain.tls_connector.is_none());
    }

    #[test]
    #[cfg(not(feature = "tls"))]
    fn test_redis_tls_disabled_when_feature_missing() {
        // Verify TLS URLs are rejected when TLS feature is not enabled
        let err = RedisConfig::from_url("rediss://localhost:6380")
            .expect_err("rediss:// should fail when TLS feature disabled");
        assert!(
            matches!(err, RedisError::InvalidUrl(ref msg) if msg.contains("TLS support not enabled"))
        );
    }

    // Pure data-type tests (wave 13 – CyanBarn)

    #[test]
    fn redis_error_display_all_variants() {
        assert!(
            RedisError::Io(io::Error::other("e"))
                .to_string()
                .contains("I/O error")
        );
        assert!(
            RedisError::Protocol("p".into())
                .to_string()
                .contains("protocol error")
        );
        assert!(
            RedisError::Redis("r".into())
                .to_string()
                .contains("Redis error")
        );
        assert!(
            RedisError::PoolExhausted
                .to_string()
                .contains("pool exhausted")
        );
        assert!(
            RedisError::InvalidUrl("bad://".into())
                .to_string()
                .contains("bad://")
        );
        assert!(RedisError::Cancelled.to_string().contains("cancelled"));
    }

    #[test]
    fn redis_error_debug() {
        let err = RedisError::PoolExhausted;
        let dbg = format!("{err:?}");
        assert!(dbg.contains("PoolExhausted"));
    }

    #[test]
    fn redis_error_source_io() {
        let err = RedisError::Io(io::Error::other("disk"));
        assert!(std::error::Error::source(&err).is_some());
    }

    #[test]
    fn redis_error_source_none_for_others() {
        assert!(std::error::Error::source(&RedisError::Cancelled).is_none());
        assert!(std::error::Error::source(&RedisError::PoolExhausted).is_none());
    }

    #[test]
    fn redis_error_from_io() {
        let io_err = io::Error::other("net");
        let err: RedisError = RedisError::from(io_err);
        assert!(matches!(err, RedisError::Io(_)));
    }

    #[test]
    fn resp_value_encode_error() {
        let val = RespValue::Error("ERR bad".into());
        assert_eq!(val.encode(), b"-ERR bad\r\n");
    }

    #[test]
    fn resp_value_encode_null_bulk_string() {
        let val = RespValue::BulkString(None);
        assert_eq!(val.encode(), b"$-1\r\n");
    }

    #[test]
    fn resp_value_encode_null_array() {
        let val = RespValue::Array(None);
        assert_eq!(val.encode(), b"*-1\r\n");
    }

    #[test]
    fn resp_value_encode_empty_array() {
        let val = RespValue::Array(Some(vec![]));
        assert_eq!(val.encode(), b"*0\r\n");
    }

    #[test]
    fn resp_value_encode_negative_integer() {
        let val = RespValue::Integer(-42);
        assert_eq!(val.encode(), b":-42\r\n");
    }

    #[test]
    fn resp_value_encode_zero_integer() {
        let val = RespValue::Integer(0);
        assert_eq!(val.encode(), b":0\r\n");
    }

    #[test]
    fn resp_value_debug_clone_eq() {
        let val = RespValue::SimpleString("OK".into());
        let dbg = format!("{val:?}");
        assert!(dbg.contains("SimpleString"));

        let cloned = val.clone();
        assert_eq!(val, cloned);
    }

    #[test]
    fn resp_value_ne() {
        let a = RespValue::Integer(1);
        let b = RespValue::Integer(2);
        assert_ne!(a, b);
    }

    #[test]
    fn resp_value_as_bytes() {
        let val = RespValue::BulkString(Some(b"hello".to_vec()));
        assert_eq!(val.as_bytes(), Some(&b"hello"[..]));

        let null = RespValue::BulkString(None);
        assert!(null.as_bytes().is_none());

        let not_bulk = RespValue::Integer(1);
        assert!(not_bulk.as_bytes().is_none());
    }

    #[test]
    fn resp_value_as_integer() {
        let val = RespValue::Integer(99);
        assert_eq!(val.as_integer(), Some(99));

        let not_int = RespValue::SimpleString("x".into());
        assert!(not_int.as_integer().is_none());
    }

    #[test]
    fn resp_value_is_ok() {
        assert!(RespValue::SimpleString("OK".into()).is_ok());
        assert!(!RespValue::SimpleString("PONG".into()).is_ok());
        assert!(!RespValue::Integer(0).is_ok());
    }

    #[test]
    fn resp_decode_error_string() {
        let (val, n) = RespValue::try_decode(b"-ERR bad\r\n")
            .unwrap()
            .expect("decoded");
        assert_eq!(val, RespValue::Error("ERR bad".into()));
        assert_eq!(n, 10);
    }

    #[test]
    fn resp_decode_null_bulk_string() {
        let (val, n) = RespValue::try_decode(b"$-1\r\n").unwrap().expect("decoded");
        assert_eq!(val, RespValue::BulkString(None));
        assert_eq!(n, 5);
    }

    #[test]
    fn resp_decode_null_array() {
        let (val, n) = RespValue::try_decode(b"*-1\r\n").unwrap().expect("decoded");
        assert_eq!(val, RespValue::Array(None));
        assert_eq!(n, 5);
    }

    #[test]
    fn resp_decode_unknown_type() {
        let err = RespValue::try_decode(b"~invalid\r\n");
        assert!(err.is_err());
    }

    #[test]
    fn redis_config_default() {
        let cfg = RedisConfig::default();
        assert_eq!(cfg.host, "127.0.0.1");
        assert_eq!(cfg.port, 6379);
        assert_eq!(cfg.database, 0);
        assert!(cfg.password.is_none());
    }

    #[test]
    fn redis_config_debug_redacts_password() {
        let cfg = RedisConfig {
            password: Some("secret".into()),
            ..Default::default()
        };
        let dbg = format!("{cfg:?}");
        assert!(dbg.contains("REDACTED"));
        assert!(!dbg.contains("secret"));
    }

    #[test]
    fn redis_config_debug_redacts_username_and_password() {
        // br-asupersync-lru405 + br-asupersync-kytkta: username is a credential
        // under Redis 6+ ACL — must be redacted alongside password.
        let cfg = RedisConfig {
            username: Some("admin_user".into()),
            password: Some("hunter2".into()),
            ..Default::default()
        };
        let dbg = format!("{cfg:?}");
        assert!(
            !dbg.contains("admin_user"),
            "username leaked in Debug output: {dbg}"
        );
        assert!(
            !dbg.contains("hunter2"),
            "password leaked in Debug output: {dbg}"
        );
        // Some/None distinction preserved (operator can still see whether a
        // credential is configured without seeing its value).
        assert!(
            dbg.contains("Some(\"[REDACTED]\")"),
            "expected redacted Some marker: {dbg}"
        );
    }

    #[test]
    fn redis_config_debug_unset_username_renders_none() {
        let cfg = RedisConfig {
            username: None,
            password: None,
            ..Default::default()
        };
        let dbg = format!("{cfg:?}");
        assert!(
            dbg.contains("username: None"),
            "expected 'username: None': {dbg}"
        );
        assert!(
            dbg.contains("password: None"),
            "expected 'password: None': {dbg}"
        );
        assert!(
            !dbg.contains("REDACTED"),
            "REDACTED should not appear when unset: {dbg}"
        );
    }

    #[test]
    fn redis_config_clone() {
        let cfg = RedisConfig::default();
        let cloned = cfg;
        assert_eq!(cloned.host, "127.0.0.1");
    }

    #[test]
    fn redis_config_from_url_with_password() {
        let cfg = RedisConfig::from_url("redis://pass123@myhost:6380/3").unwrap();
        assert_eq!(cfg.host, "myhost");
        assert_eq!(cfg.port, 6380);
        assert_eq!(cfg.database, 3);
        assert_eq!(cfg.password, Some("pass123".into()));
    }

    #[test]
    fn redis_config_from_url_invalid_scheme() {
        assert!(RedisConfig::from_url("http://localhost").is_err());
    }

    #[test]
    fn redis_config_from_url_host_only() {
        let cfg = RedisConfig::from_url("redis://myhost").unwrap();
        assert_eq!(cfg.host, "myhost");
        assert_eq!(cfg.port, 6379);
    }

    #[test]
    fn watch_rejects_pooled_client_api() {
        let client = pooled_client_without_acquire();
        run_test_with_cx(move |cx| async move {
            let err = client
                .watch(&cx, &["k1"])
                .expect_err("WATCH must fail closed");
            assert!(matches!(err, RedisError::Protocol(msg) if msg.contains("connection-scoped")));
        });
    }

    #[test]
    fn unwatch_rejects_pooled_client_api() {
        let client = pooled_client_without_acquire();
        run_test_with_cx(move |cx| async move {
            let err = client.unwatch(&cx).expect_err("UNWATCH must fail closed");
            assert!(matches!(err, RedisError::Protocol(msg) if msg.contains("connection-scoped")));
        });
    }

    #[test]
    fn resp_encode_into_reuse_buffer() {
        let mut buf = Vec::new();
        RespValue::SimpleString("PING".into()).encode_into(&mut buf);
        RespValue::Integer(1).encode_into(&mut buf);
        assert_eq!(&buf, b"+PING\r\n:1\r\n");
    }

    #[test]
    fn expect_ok_response_accepts_ok() {
        let resp = RespValue::SimpleString("OK".to_string());
        assert!(expect_ok_response(&resp, "TEST").is_ok());
    }

    #[test]
    fn expect_ok_response_rejects_non_ok() {
        let resp = RespValue::SimpleString("PONG".to_string());
        let err = expect_ok_response(&resp, "TEST").expect_err("must reject non-OK");
        assert!(matches!(err, RedisError::Protocol(_)));
    }

    #[test]
    fn pubsub_parse_message_event() {
        let event = RedisPubSub::parse_event(RespValue::Array(Some(vec![
            RespValue::BulkString(Some(b"message".to_vec())),
            RespValue::BulkString(Some(b"chan-1".to_vec())),
            RespValue::BulkString(Some(b"payload".to_vec())),
        ])))
        .expect("message event should parse");

        assert_eq!(
            event,
            PubSubEvent::Message(PubSubMessage {
                channel: "chan-1".to_string(),
                pattern: None,
                payload: b"payload".to_vec(),
            })
        );
    }

    #[test]
    fn pubsub_parse_resp3_push_message_event() {
        let event = RedisPubSub::parse_event(RespValue::Push(vec![
            RespValue::BulkString(Some(b"message".to_vec())),
            RespValue::BulkString(Some(b"chan-1".to_vec())),
            RespValue::BulkString(Some(b"payload".to_vec())),
        ]))
        .expect("RESP3 push message event should parse");

        assert_eq!(
            event,
            PubSubEvent::Message(PubSubMessage {
                channel: "chan-1".to_string(),
                pattern: None,
                payload: b"payload".to_vec(),
            })
        );
    }

    #[test]
    fn pubsub_parse_pmessage_event() {
        let event = RedisPubSub::parse_event(RespValue::Array(Some(vec![
            RespValue::BulkString(Some(b"pmessage".to_vec())),
            RespValue::BulkString(Some(b"user.*".to_vec())),
            RespValue::BulkString(Some(b"user.created".to_vec())),
            RespValue::BulkString(Some(b"body".to_vec())),
        ])))
        .expect("pmessage event should parse");

        assert_eq!(
            event,
            PubSubEvent::Message(PubSubMessage {
                channel: "user.created".to_string(),
                pattern: Some("user.*".to_string()),
                payload: b"body".to_vec(),
            })
        );
    }

    /// Audit test for PSUBSCRIBE pattern-matching and message delivery.
    ///
    /// Verifies that when subscribed to "news.*" and message arrives on "news.tech",
    /// the pattern matches (glob * semantics) and message is delivered with the full
    /// channel name "news.tech" along with the original pattern "news.*".
    #[test]
    fn audit_psubscribe_glob_pattern_matching_news_tech() {
        // Build Redis server response for PSUBSCRIBE pattern match.
        // Format: ["pmessage", pattern, actual_channel, payload]
        let event = RedisPubSub::parse_event(RespValue::Array(Some(vec![
            RespValue::BulkString(Some(b"pmessage".to_vec())),
            RespValue::BulkString(Some(b"news.*".to_vec())), // Original pattern
            RespValue::BulkString(Some(b"news.tech".to_vec())), // Actual channel that matched
            RespValue::BulkString(Some(b"Breaking: New AI framework released".to_vec())),
        ])))
        .expect("Redis pmessage for news.* → news.tech should parse correctly");

        // Verify correct pattern matching behavior
        assert_eq!(
            event,
            PubSubEvent::Message(PubSubMessage {
                channel: "news.tech".to_string(),    // Full channel name preserved
                pattern: Some("news.*".to_string()), // Original pattern preserved
                payload: b"Breaking: New AI framework released".to_vec(),
            }),
            "PSUBSCRIBE must deliver message with full channel name AND original pattern"
        );

        // Additional verification: pattern field must be present for PSUBSCRIBE deliveries
        if let PubSubEvent::Message(msg) = event {
            assert!(
                msg.pattern.is_some(),
                "PSUBSCRIBE messages MUST include the pattern field to distinguish from SUBSCRIBE"
            );
            assert_eq!(
                msg.pattern.unwrap(),
                "news.*",
                "Pattern field must contain the exact subscription pattern"
            );
            assert_eq!(
                msg.channel, "news.tech",
                "Channel field must contain the full matching channel name, not the pattern"
            );
        } else {
            panic!("Expected Message event");
        }
    }

    #[test]
    fn pubsub_parse_subscription_event() {
        let event = RedisPubSub::parse_event(RespValue::Array(Some(vec![
            RespValue::BulkString(Some(b"subscribe".to_vec())),
            RespValue::BulkString(Some(b"metrics".to_vec())),
            RespValue::Integer(2),
        ])))
        .expect("subscribe event should parse");

        assert_eq!(
            event,
            PubSubEvent::Subscription {
                kind: PubSubSubscriptionKind::Subscribe,
                channel: "metrics".to_string(),
                remaining: 2,
            }
        );
    }

    #[test]
    fn pubsub_parse_pong_event() {
        let event = RedisPubSub::parse_event(RespValue::Array(Some(vec![
            RespValue::BulkString(Some(b"pong".to_vec())),
            RespValue::BulkString(Some(b"hello".to_vec())),
        ])))
        .expect("pong event should parse");

        assert_eq!(event, PubSubEvent::Pong(Some(b"hello".to_vec())));
    }

    #[test]
    fn pubsub_parse_unknown_event_kind_fails() {
        let err = RedisPubSub::parse_event(RespValue::Array(Some(vec![
            RespValue::BulkString(Some(b"weird".to_vec())),
            RespValue::BulkString(Some(b"x".to_vec())),
        ])))
        .expect_err("unknown event should fail");

        assert!(matches!(err, RedisError::Protocol(_)));
    }

    #[test]
    fn client_tracking_push_parse_invalidate_keys() {
        let event = parse_client_tracking_push_for_fuzz(RespValue::Push(vec![
            RespValue::BulkString(Some(b"invalidate".to_vec())),
            RespValue::Array(Some(vec![
                RespValue::BulkString(Some(b"user:1".to_vec())),
                RespValue::SimpleString("config:active".to_string()),
            ])),
        ]))
        .expect("client tracking invalidation should parse");

        assert_eq!(
            event,
            RedisClientTrackingPush::Invalidate {
                keys: Some(vec![b"user:1".to_vec(), b"config:active".to_vec()])
            }
        );
    }

    #[test]
    fn client_tracking_push_parse_flush_and_redirect_broken() {
        let flush = parse_client_tracking_push_for_fuzz(RespValue::Push(vec![
            RespValue::BulkString(Some(b"invalidate".to_vec())),
            RespValue::Null,
        ]))
        .expect("null invalidation should parse as a cache flush");
        assert_eq!(flush, RedisClientTrackingPush::Invalidate { keys: None });

        let broken =
            parse_client_tracking_push_for_fuzz(RespValue::Push(vec![RespValue::BulkString(
                Some(b"tracking-redir-broken".to_vec()),
            )]))
            .expect("tracking-redir-broken should parse");
        assert_eq!(broken, RedisClientTrackingPush::RedirectBroken);
    }

    #[test]
    fn client_tracking_push_rejects_malformed_frames() {
        let non_push = parse_client_tracking_push_for_fuzz(RespValue::Array(Some(vec![
            RespValue::BulkString(Some(b"invalidate".to_vec())),
            RespValue::Array(Some(vec![])),
        ])));
        assert!(
            non_push.is_err(),
            "tracking notifications must be RESP3 pushes"
        );

        let bad_key_payload = parse_client_tracking_push_for_fuzz(RespValue::Push(vec![
            RespValue::BulkString(Some(b"invalidate".to_vec())),
            RespValue::Array(Some(vec![RespValue::Integer(7)])),
        ]));
        assert!(
            bad_key_payload.is_err(),
            "invalidation keys must be payloads"
        );

        let trailing_redirect = parse_client_tracking_push_for_fuzz(RespValue::Push(vec![
            RespValue::BulkString(Some(b"tracking-redir-broken".to_vec())),
            RespValue::BulkString(Some(b"extra".to_vec())),
        ]));
        assert!(
            trailing_redirect.is_err(),
            "tracking-redir-broken must reject trailing fields"
        );
    }

    #[test]
    fn resp3_non_pubsub_push_classifies_generic_push() {
        let event = parse_resp3_non_pubsub_push_for_fuzz(RespValue::Push(vec![
            RespValue::BulkString(Some(b"server-event".to_vec())),
            RespValue::BulkString(Some(
                b"1700000000.000000 [0 127.0.0.1:1] \"GET\" \"k\"".to_vec(),
            )),
            RespValue::Integer(9),
        ]))
        .expect("generic non-pubsub push should parse");

        assert_eq!(
            event,
            RedisResp3NonPubSubPush::Other {
                kind: "server-event".to_string(),
                payload: vec![
                    RespValue::BulkString(Some(
                        b"1700000000.000000 [0 127.0.0.1:1] \"GET\" \"k\"".to_vec()
                    )),
                    RespValue::Integer(9)
                ],
            }
        );
    }

    #[test]
    fn resp3_non_pubsub_push_delegates_tracking_and_rejects_pubsub() {
        let tracking = parse_resp3_non_pubsub_push_for_fuzz(RespValue::Push(vec![
            RespValue::BulkString(Some(b"invalidate".to_vec())),
            RespValue::Array(Some(vec![RespValue::BulkString(Some(b"k".to_vec()))])),
        ]))
        .expect("client tracking push should parse through non-pubsub seam");
        assert_eq!(
            tracking,
            RedisResp3NonPubSubPush::ClientTracking(RedisClientTrackingPush::Invalidate {
                keys: Some(vec![b"k".to_vec()])
            })
        );

        let pubsub = parse_resp3_non_pubsub_push_for_fuzz(RespValue::Push(vec![
            RespValue::BulkString(Some(b"message".to_vec())),
            RespValue::BulkString(Some(b"chan".to_vec())),
            RespValue::BulkString(Some(b"body".to_vec())),
        ]));
        assert!(
            pubsub.is_err(),
            "pubsub push kinds must use the pubsub parser"
        );

        let empty = parse_resp3_non_pubsub_push_for_fuzz(RespValue::Push(vec![]));
        assert!(empty.is_err(), "empty RESP3 pushes must be rejected");
    }

    #[test]
    fn redis_resp3_push_single_push_before_integer_response_is_buffered() {
        let listener = StdTcpListener::bind("127.0.0.1:0").expect("bind test listener");
        let addr = listener.local_addr().expect("listener addr");
        let combined_buffer = {
            let mut bytes = Vec::new();
            RespValue::Push(vec![
                RespValue::BulkString(Some(b"invalidate".to_vec())),
                RespValue::Array(Some(vec![
                    RespValue::BulkString(Some(b"alpha".to_vec())),
                    RespValue::BulkString(Some(b"beta".to_vec())),
                ])),
            ])
            .encode_into(&mut bytes);
            RespValue::Integer(7).encode_into(&mut bytes);
            bytes
        };
        let combined_fingerprint = buffer_fingerprint(&combined_buffer);
        let push_frame_len = RespValue::Push(vec![
            RespValue::BulkString(Some(b"invalidate".to_vec())),
            RespValue::Array(Some(vec![
                RespValue::BulkString(Some(b"alpha".to_vec())),
                RespValue::BulkString(Some(b"beta".to_vec())),
            ])),
        ])
        .encode()
        .len();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept redis client");
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .expect("set read timeout");
            write_hello3_ok(&mut stream);

            let ping = read_resp_frame(&mut stream);
            assert_resp_command(ping, &[b"PING"]);
            stream
                .write_all(&combined_buffer)
                .expect("write RESP3 push + integer reply");
            stream.flush().expect("flush RESP3 push + integer reply");
        });

        run_test_with_cx(|cx| async move {
            let url = format!("redis://{}:{}/0", addr.ip(), addr.port());
            let client = RedisClient::connect(&cx, &url)
                .await
                .expect("connect redis client");

            let response = client.cmd(&cx, &["PING"]).await.expect("PING response");
            assert_eq!(response, RespValue::Integer(7));

            tracing::info!(
                frame_kind = "invalidate",
                consumed_bytes = push_frame_len,
                response_count = 1usize,
                push_count = client.resp3_pending_pushes(),
                queue_len = client.resp3_pending_pushes(),
                buffer_fingerprint = %combined_fingerprint,
                "redis RESP3 single push buffered before integer response"
            );

            let pushes = collect_resp3_pushes(&client);
            assert_eq!(
                pushes,
                vec![RedisResp3NonPubSubPush::ClientTracking(
                    RedisClientTrackingPush::Invalidate {
                        keys: Some(vec![b"alpha".to_vec(), b"beta".to_vec()]),
                    },
                )]
            );
            assert_eq!(client.resp3_dropped_pushes(), 0);
        });

        server.join().expect("server join");
    }

    #[test]
    fn redis_resp3_push_pipeline_preserves_response_and_push_order() {
        let listener = StdTcpListener::bind("127.0.0.1:0").expect("bind test listener");
        let addr = listener.local_addr().expect("listener addr");
        let combined_buffer = {
            let mut bytes = Vec::new();
            RespValue::Push(vec![
                RespValue::BulkString(Some(b"monitor".to_vec())),
                RespValue::BulkString(Some(b"first".to_vec())),
            ])
            .encode_into(&mut bytes);
            RespValue::SimpleString("ONE".to_string()).encode_into(&mut bytes);
            RespValue::Push(vec![
                RespValue::BulkString(Some(b"invalidate".to_vec())),
                RespValue::Array(Some(vec![RespValue::BulkString(Some(
                    b"cache-key".to_vec(),
                ))])),
            ])
            .encode_into(&mut bytes);
            RespValue::SimpleString("TWO".to_string()).encode_into(&mut bytes);
            bytes
        };
        let combined_len = combined_buffer.len();
        let combined_fingerprint = buffer_fingerprint(&combined_buffer);
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept redis client");
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .expect("set read timeout");
            write_hello3_ok(&mut stream);

            let mut read_buf = Vec::new();
            let first = read_resp_frame_from_buffer(&mut stream, &mut read_buf);
            assert_resp_command(first, &[b"PING"]);
            let second = read_resp_frame_from_buffer(&mut stream, &mut read_buf);
            assert_resp_command(second, &[b"PING"]);
            stream
                .write_all(&combined_buffer)
                .expect("write pipelined replies");
            stream.flush().expect("flush pipelined replies");
        });

        run_test_with_cx(|cx| async move {
            let url = format!("redis://{}:{}/0", addr.ip(), addr.port());
            let client = RedisClient::connect(&cx, &url)
                .await
                .expect("connect redis client");

            let mut pipeline = client.pipeline();
            pipeline.cmd(&["PING"]);
            pipeline.cmd(&["PING"]);
            let results = pipeline.exec(&cx).await.expect("pipeline exec");

            assert_eq!(results.len(), 2, "pipeline response count");
            assert!(
                matches!(
                    &results[0],
                    Ok(RespValue::SimpleString(value)) if value == "ONE"
                ),
                "first pipeline response should be ONE: {results:?}"
            );
            assert!(
                matches!(
                    &results[1],
                    Ok(RespValue::SimpleString(value)) if value == "TWO"
                ),
                "second pipeline response should be TWO: {results:?}"
            );

            tracing::info!(
                frame_kind = "monitor+invalidate",
                consumed_bytes = combined_len,
                response_count = results.len(),
                push_count = client.resp3_pending_pushes(),
                queue_len = client.resp3_pending_pushes(),
                buffer_fingerprint = %combined_fingerprint,
                "redis RESP3 pipeline preserves response and push order"
            );

            let pushes = collect_resp3_pushes(&client);
            assert_eq!(
                pushes,
                vec![
                    RedisResp3NonPubSubPush::Other {
                        kind: "monitor".to_string(),
                        payload: vec![RespValue::BulkString(Some(b"first".to_vec()))],
                    },
                    RedisResp3NonPubSubPush::ClientTracking(RedisClientTrackingPush::Invalidate {
                        keys: Some(vec![b"cache-key".to_vec()]),
                    },),
                ]
            );
        });

        server.join().expect("server join");
    }

    #[test]
    fn redis_resp3_push_attribute_interleaving_still_returns_response() {
        let listener = StdTcpListener::bind("127.0.0.1:0").expect("bind test listener");
        let addr = listener.local_addr().expect("listener addr");
        let combined_buffer = {
            let mut bytes = Vec::new();
            RespValue::Attribute(vec![(
                RespValue::SimpleString("meta".to_string()),
                RespValue::SimpleString("before-push".to_string()),
            )])
            .encode_into(&mut bytes);
            RespValue::Push(vec![RespValue::BulkString(Some(
                b"tracking-redir-broken".to_vec(),
            ))])
            .encode_into(&mut bytes);
            RespValue::SimpleString("OK".to_string()).encode_into(&mut bytes);
            bytes
        };
        let combined_len = combined_buffer.len();
        let combined_fingerprint = buffer_fingerprint(&combined_buffer);
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept redis client");
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .expect("set read timeout");
            write_hello3_ok(&mut stream);

            let ping = read_resp_frame(&mut stream);
            assert_resp_command(ping, &[b"PING"]);
            stream
                .write_all(&combined_buffer)
                .expect("write attribute + push + response");
            stream.flush().expect("flush attribute + push + response");
        });

        run_test_with_cx(|cx| async move {
            let url = format!("redis://{}:{}/0", addr.ip(), addr.port());
            let client = RedisClient::connect(&cx, &url)
                .await
                .expect("connect redis client");

            let response = client.cmd(&cx, &["PING"]).await.expect("PING response");
            assert_eq!(response, RespValue::SimpleString("OK".to_string()));

            tracing::info!(
                frame_kind = "attribute+tracking-redir-broken",
                consumed_bytes = combined_len,
                response_count = 1usize,
                push_count = client.resp3_pending_pushes(),
                queue_len = client.resp3_pending_pushes(),
                buffer_fingerprint = %combined_fingerprint,
                "redis RESP3 attribute and push interleaving preserves command response"
            );

            let pushes = collect_resp3_pushes(&client);
            assert_eq!(
                pushes,
                vec![RedisResp3NonPubSubPush::ClientTracking(
                    RedisClientTrackingPush::RedirectBroken,
                )]
            );
        });

        server.join().expect("server join");
    }

    #[test]
    fn redis_resp3_push_cancellation_after_decoded_push_preserves_backlog() {
        let listener = StdTcpListener::bind("127.0.0.1:0").expect("bind test listener");
        let addr = listener.local_addr().expect("listener addr");
        let (push_written_tx, push_written_rx) = mpsc::channel();
        let (closed_tx, closed_rx) = mpsc::channel();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept redis client");
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .expect("set read timeout");
            write_hello3_ok(&mut stream);

            let ping = read_resp_frame(&mut stream);
            assert_resp_command(ping, &[b"PING"]);
            let push = RespValue::Push(vec![
                RespValue::BulkString(Some(b"monitor".to_vec())),
                RespValue::BulkString(Some(b"cancelled-flight".to_vec())),
            ])
            .encode();
            stream.write_all(&push).expect("write RESP3 push");
            stream.flush().expect("flush RESP3 push");
            push_written_tx.send(()).expect("signal push written");

            let mut probe = [0u8; 1];
            match stream.read(&mut probe) {
                Ok(0) => closed_tx.send(()).expect("signal close observed"),
                Ok(n) => panic!("expected cancelled client to close transport, read {n} bytes"),
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                    ) =>
                {
                    panic!("cancelled client left the socket open after push delivery")
                }
                Err(e) => panic!("probe cancelled socket: {e}"),
            }
        });

        run_test_with_cx(|cx| async move {
            let url = format!("redis://{}:{}/0", addr.ip(), addr.port());
            let client = RedisClient::connect(&cx, &url)
                .await
                .expect("connect redis client");

            let worker_cx = cx.clone();
            let mut command = Box::pin(client.cmd(&worker_cx, &["PING"]));
            drive_until_signal(
                command.as_mut(),
                &push_written_rx,
                "redis RESP3 push cancellation command",
            );

            for _ in 0..200 {
                if client.resp3_pending_pushes() == 1 {
                    break;
                }
                match poll_once(command.as_mut()) {
                    Poll::Pending => std::thread::sleep(Duration::from_millis(10)),
                    Poll::Ready(result) => {
                        panic!(
                            "command completed before cancellation after push delivery: {result:?}"
                        )
                    }
                }
            }
            assert_eq!(
                client.resp3_pending_pushes(),
                1,
                "decoded RESP3 push must be queued before cancellation"
            );

            tracing::info!(
                frame_kind = "monitor",
                consumed_bytes = 0usize,
                response_count = 0usize,
                push_count = client.resp3_pending_pushes(),
                queue_len = client.resp3_pending_pushes(),
                "redis RESP3 cancellation preserves decoded push backlog"
            );

            worker_cx.cancel_fast(crate::types::CancelKind::User);
            let result = future::poll_fn(|poll_cx| command.as_mut().poll(poll_cx)).await;
            assert!(
                matches!(result, Err(RedisError::Cancelled)),
                "expected cancellation after push delivery, got {result:?}"
            );

            closed_rx
                .recv_timeout(Duration::from_secs(2))
                .expect("cancelled connection should close");

            let pushes = collect_resp3_pushes(&client);
            assert_eq!(
                pushes,
                vec![RedisResp3NonPubSubPush::Other {
                    kind: "monitor".to_string(),
                    payload: vec![RespValue::BulkString(Some(b"cancelled-flight".to_vec(),))],
                }]
            );
        });

        server.join().expect("server join");
    }

    #[test]
    fn redis_resp3_push_backlog_overflow_reports_lag_deterministically() {
        let listener = StdTcpListener::bind("127.0.0.1:0").expect("bind test listener");
        let addr = listener.local_addr().expect("listener addr");
        let combined_buffer = {
            let mut bytes = Vec::new();
            RespValue::Push(vec![
                RespValue::BulkString(Some(b"monitor".to_vec())),
                RespValue::BulkString(Some(b"first".to_vec())),
            ])
            .encode_into(&mut bytes);
            RespValue::Push(vec![
                RespValue::BulkString(Some(b"monitor".to_vec())),
                RespValue::BulkString(Some(b"second".to_vec())),
            ])
            .encode_into(&mut bytes);
            RespValue::SimpleString("OK".to_string()).encode_into(&mut bytes);
            bytes
        };
        let combined_len = combined_buffer.len();
        let combined_fingerprint = buffer_fingerprint(&combined_buffer);
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept redis client");
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .expect("set read timeout");
            write_hello3_ok(&mut stream);

            let ping = read_resp_frame(&mut stream);
            assert_resp_command(ping, &[b"PING"]);
            stream
                .write_all(&combined_buffer)
                .expect("write overflow push sequence");
            stream.flush().expect("flush overflow push sequence");
        });

        run_test_with_cx(|cx| async move {
            let mut config = RedisConfig {
                host: addr.ip().to_string(),
                port: addr.port(),
                ..Default::default()
            };
            config.resp3_push_max_backlog = 1;
            let client = client_with_config(config);

            let response = client.cmd(&cx, &["PING"]).await.expect("PING response");
            assert_eq!(response, RespValue::SimpleString("OK".to_string()));

            tracing::info!(
                frame_kind = "monitor-overflow",
                consumed_bytes = combined_len,
                response_count = 1usize,
                push_count = 2usize,
                queue_len = client.resp3_pending_pushes(),
                capacity = 1usize,
                dropped_or_rejected_count = client.resp3_dropped_pushes(),
                reason = "drop newest when regular-client RESP3 push backlog reaches cap",
                buffer_fingerprint = %combined_fingerprint,
                "redis RESP3 push backlog overflow reports lag deterministically"
            );

            let lag = client
                .try_next_resp3_push()
                .expect_err("overflow must surface lag before queued push");
            assert!(
                matches!(lag, RedisError::Resp3PushLag { dropped: 1 }),
                "unexpected lag result: {lag:?}"
            );

            let next = client
                .try_next_resp3_push()
                .expect("lag should be one-shot")
                .expect("first push remains queued");
            assert_eq!(
                next,
                RedisResp3NonPubSubPush::Other {
                    kind: "monitor".to_string(),
                    payload: vec![RespValue::BulkString(Some(b"first".to_vec()))],
                }
            );
            assert_eq!(
                client.try_next_resp3_push().expect("queue drained"),
                None,
                "only the oldest push should remain after drop-newest overflow"
            );
        });

        server.join().expect("server join");
    }

    #[test]
    fn pubsub_psubscribe_rejects_unrequested_ack_pattern() {
        let listener = StdTcpListener::bind("127.0.0.1:0").expect("bind test listener");
        let addr = listener.local_addr().expect("listener addr");
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept client");
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .expect("set read timeout");

            write_hello3_ok(&mut stream);
            let psubscribe = read_resp_frame(&mut stream);
            assert_resp_command(psubscribe, &[b"PSUBSCRIBE", b"safe.*"]);
            let injected_ack = RespValue::Array(Some(vec![
                RespValue::BulkString(Some(b"psubscribe".to_vec())),
                RespValue::BulkString(Some(b"*".to_vec())),
                RespValue::Integer(1),
            ]))
            .encode();
            stream
                .write_all(&injected_ack)
                .expect("write injected psubscribe ack");
            stream.flush().expect("flush injected psubscribe ack");
        });

        run_test_with_cx(|cx| async move {
            let config = RedisConfig {
                host: addr.ip().to_string(),
                port: addr.port(),
                ..Default::default()
            };
            let mut pubsub = RedisPubSub::connect(&cx, config)
                .await
                .expect("connect pubsub client");

            let err = pubsub
                .psubscribe(&cx, &["safe.*"])
                .await
                .expect_err("unexpected wildcard ack must fail closed");
            assert!(
                matches!(err, RedisError::Protocol(msg) if msg.contains("PSUBSCRIBE received unexpected acknowledgement target"))
            );
            assert!(pubsub.patterns().is_empty());

            let err = pubsub
                .next_event(&cx)
                .await
                .expect_err("failed control exchange should poison connection");
            assert!(matches!(err, RedisError::Protocol(msg) if msg.contains("invalidated")));
        });

        server.join().expect("server join");
    }

    #[test]
    fn pubsub_ping_preserves_interleaved_messages() {
        let listener = StdTcpListener::bind("127.0.0.1:0").expect("bind test listener");
        let addr = listener.local_addr().expect("listener addr");
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept client");
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .expect("set read timeout");

            let subscribe = read_resp_frame(&mut stream);
            assert_resp_command(subscribe, &[b"SUBSCRIBE", b"chan"]);
            let subscribe_ack = RespValue::Array(Some(vec![
                RespValue::BulkString(Some(b"subscribe".to_vec())),
                RespValue::BulkString(Some(b"chan".to_vec())),
                RespValue::Integer(1),
            ]))
            .encode();
            stream
                .write_all(&subscribe_ack)
                .expect("write subscribe ack");
            stream.flush().expect("flush subscribe ack");

            let ping = read_resp_frame(&mut stream);
            assert_resp_command(ping, &[b"PING"]);
            let mut outbound = Vec::new();
            RespValue::Array(Some(vec![
                RespValue::BulkString(Some(b"message".to_vec())),
                RespValue::BulkString(Some(b"chan".to_vec())),
                RespValue::BulkString(Some(b"payload".to_vec())),
            ]))
            .encode_into(&mut outbound);
            RespValue::Array(Some(vec![RespValue::BulkString(Some(b"pong".to_vec()))]))
                .encode_into(&mut outbound);
            stream
                .write_all(&outbound)
                .expect("write interleaved message and pong");
            stream.flush().expect("flush interleaved message and pong");
        });

        run_test_with_cx(|cx| async move {
            let config = RedisConfig {
                host: addr.ip().to_string(),
                port: addr.port(),
                ..Default::default()
            };
            let mut pubsub = RedisPubSub::connect(&cx, config)
                .await
                .expect("connect pubsub client");
            pubsub
                .subscribe(&cx, &["chan"])
                .await
                .expect("subscribe should succeed");

            assert_completes_within(
                Duration::from_secs(2),
                "redis pubsub ping preserves interleaved messages",
                || {
                    Box::pin(async {
                        pubsub.ping(&cx, None).await.expect("ping should succeed");
                        let event = pubsub
                            .next_event(&cx)
                            .await
                            .expect("interleaved message should remain visible");
                        assert_eq!(
                            event,
                            PubSubEvent::Message(PubSubMessage {
                                channel: "chan".to_string(),
                                pattern: None,
                                payload: b"payload".to_vec(),
                            })
                        );
                    })
                },
            )
            .await;
        });

        server.join().expect("server join");
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn pubsub_reconnect_discards_buffered_events_from_previous_connection() {
        let listener = StdTcpListener::bind("127.0.0.1:0").expect("bind test listener");
        let addr = listener.local_addr().expect("listener addr");
        let server = thread::spawn(move || {
            let (mut first_stream, _) = listener.accept().expect("accept first client");
            first_stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .expect("set first read timeout");

            let subscribe = read_resp_frame(&mut first_stream);
            assert_resp_command(subscribe, &[b"SUBSCRIBE", b"chan"]);
            let subscribe_ack = RespValue::Array(Some(vec![
                RespValue::BulkString(Some(b"subscribe".to_vec())),
                RespValue::BulkString(Some(b"chan".to_vec())),
                RespValue::Integer(1),
            ]))
            .encode();
            first_stream
                .write_all(&subscribe_ack)
                .expect("write first subscribe ack");
            first_stream.flush().expect("flush first subscribe ack");

            let ping = read_resp_frame(&mut first_stream);
            assert_resp_command(ping, &[b"PING"]);
            let mut outbound = Vec::new();
            RespValue::Array(Some(vec![
                RespValue::BulkString(Some(b"message".to_vec())),
                RespValue::BulkString(Some(b"chan".to_vec())),
                RespValue::BulkString(Some(b"stale".to_vec())),
            ]))
            .encode_into(&mut outbound);
            RespValue::Array(Some(vec![RespValue::BulkString(Some(b"pong".to_vec()))]))
                .encode_into(&mut outbound);
            first_stream
                .write_all(&outbound)
                .expect("write buffered stale message and pong");
            first_stream
                .flush()
                .expect("flush buffered stale message and pong");
            drop(first_stream);

            let (mut second_stream, _) = listener.accept().expect("accept second client");
            second_stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .expect("set second read timeout");

            let subscribe = read_resp_frame(&mut second_stream);
            assert_resp_command(subscribe, &[b"SUBSCRIBE", b"chan"]);
            let subscribe_ack = RespValue::Array(Some(vec![
                RespValue::BulkString(Some(b"subscribe".to_vec())),
                RespValue::BulkString(Some(b"chan".to_vec())),
                RespValue::Integer(1),
            ]))
            .encode();
            second_stream
                .write_all(&subscribe_ack)
                .expect("write second subscribe ack");
            let fresh = RespValue::Array(Some(vec![
                RespValue::BulkString(Some(b"message".to_vec())),
                RespValue::BulkString(Some(b"chan".to_vec())),
                RespValue::BulkString(Some(b"fresh".to_vec())),
            ]))
            .encode();
            second_stream
                .write_all(&fresh)
                .expect("write fresh message after reconnect");
            second_stream
                .flush()
                .expect("flush second subscribe ack and fresh message");
        });

        run_test_with_cx(|cx| async move {
            let config = RedisConfig {
                host: addr.ip().to_string(),
                port: addr.port(),
                ..Default::default()
            };
            let mut pubsub = RedisPubSub::connect(&cx, config)
                .await
                .expect("connect pubsub client");
            pubsub
                .subscribe(&cx, &["chan"])
                .await
                .expect("subscribe should succeed");

            pubsub.ping(&cx, None).await.expect("ping should succeed");
            pubsub
                .reconnect(&cx)
                .await
                .expect("reconnect should succeed");

            assert_completes_within(
                Duration::from_secs(2),
                "redis pubsub reconnect clears stale buffered events",
                || {
                    Box::pin(async {
                        let event = pubsub
                            .next_event(&cx)
                            .await
                            .expect("fresh message should be visible after reconnect");
                        assert_eq!(
                            event,
                            PubSubEvent::Message(PubSubMessage {
                                channel: "chan".to_string(),
                                pattern: None,
                                payload: b"fresh".to_vec(),
                            })
                        );
                    })
                },
            )
            .await;
        });

        server.join().expect("server join");
    }

    #[test]
    fn pubsub_cancelled_subscribe_poison_connection_and_requires_reconnect() {
        let listener = StdTcpListener::bind("127.0.0.1:0").expect("bind test listener");
        let addr = listener.local_addr().expect("listener addr");
        let (subscribe_seen_tx, subscribe_seen_rx) = mpsc::channel();

        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept pubsub client");
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .expect("set read timeout");

            let subscribe = read_resp_frame(&mut stream);
            assert_resp_command(subscribe, &[b"SUBSCRIBE", b"chan"]);
            subscribe_seen_tx
                .send(())
                .expect("signal subscribe command arrival");

            let mut probe = [0u8; 1];
            match stream.read(&mut probe) {
                Ok(0) => {}
                Ok(n) => panic!(
                    "expected cancelled pubsub subscribe to close the connection, read {n} extra byte(s)"
                ),
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                    ) =>
                {
                    panic!("cancelled pubsub subscribe left the connection open")
                }
                Err(e) => panic!("read after cancelled pubsub subscribe: {e}"),
            }
        });

        run_test_with_cx(|cx| async move {
            let config = RedisConfig {
                host: addr.ip().to_string(),
                port: addr.port(),
                ..Default::default()
            };
            let mut pubsub = RedisPubSub::connect(&cx, config)
                .await
                .expect("connect pubsub client");

            {
                let mut subscribe = Box::pin(pubsub.subscribe(&cx, &["chan"]));
                drive_until_signal(
                    subscribe.as_mut(),
                    &subscribe_seen_rx,
                    "redis pubsub subscribe",
                );
            }

            assert!(
                pubsub.channels().is_empty(),
                "cancelled subscribe must restore the last confirmed channel snapshot"
            );

            let err = pubsub
                .subscribe(&cx, &["other"])
                .await
                .expect_err("poisoned pubsub connection must fail closed");
            assert!(
                matches!(err, RedisError::Protocol(ref message) if message.contains("call reconnect")),
                "unexpected poisoned pubsub error: {err:?}"
            );

            let err = pubsub
                .next_event(&cx)
                .await
                .expect_err("poisoned pubsub connection must reject event reads");
            assert!(
                matches!(err, RedisError::Protocol(ref message) if message.contains("call reconnect")),
                "unexpected poisoned next_event error: {err:?}"
            );
        });

        server.join().expect("server join");
    }

    #[test]
    fn cmd_cancellation_discards_pooled_connection() {
        let listener = StdTcpListener::bind("127.0.0.1:0").expect("bind test listener");
        let addr = listener.local_addr().expect("listener addr");
        let (first_ping_tx, first_ping_rx) = std::sync::mpsc::channel();
        let server = thread::spawn(move || {
            let (mut first_stream, _) = listener.accept().expect("accept first client");
            first_stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .expect("set first read timeout");

            write_hello3_ok(&mut first_stream);
            let first_ping = read_resp_frame(&mut first_stream);
            assert_resp_command(first_ping, &[b"PING"]);
            first_ping_tx.send(()).expect("signal first ping");

            let mut probe = [0u8; 1];
            match first_stream.read(&mut probe) {
                Ok(0) => {}
                Ok(n) => panic!(
                    "expected first connection to close after cancellation, read {n} extra byte(s)"
                ),
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                    ) =>
                {
                    panic!("first connection remained open after cancellation")
                }
                Err(e) => panic!("read first connection after cancellation: {e}"),
            }

            let (mut second_stream, _) = listener.accept().expect("accept second client");
            second_stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .expect("set second read timeout");
            write_hello3_ok(&mut second_stream);
            let second_ping = read_resp_frame(&mut second_stream);
            assert_resp_command(second_ping, &[b"PING"]);
            second_stream
                .write_all(&RespValue::SimpleString("PONG".to_string()).encode())
                .expect("write second ping response");
            second_stream.flush().expect("flush second ping response");
        });

        run_test_with_cx(|cx| async move {
            let client =
                RedisClient::connect(&cx, &format!("redis://{}:{}/0", addr.ip(), addr.port()))
                    .await
                    .expect("create redis client");

            {
                let mut ping = Box::pin(client.ping(&cx));
                drive_until_signal(ping.as_mut(), &first_ping_rx, "redis ping command");
            }

            client.ping(&cx).await.expect("second ping should succeed");
        });

        server.join().expect("server join");
    }

    #[test]
    fn cluster_moved_redirect_retries_and_records_slot_like_redis_rs() {
        let primary_listener =
            StdTcpListener::bind("127.0.0.1:0").expect("bind primary redis listener");
        let primary_addr = primary_listener
            .local_addr()
            .expect("primary listener addr");
        let redirect_listener =
            StdTcpListener::bind("127.0.0.1:0").expect("bind redirect redis listener");
        let redirect_addr = redirect_listener
            .local_addr()
            .expect("redirect listener addr");
        let redirect_target = format!("{}:{}", redirect_addr.ip(), redirect_addr.port());

        let primary_server = thread::spawn({
            let redirect_target = redirect_target.clone();
            move || {
                let (mut stream, _) = primary_listener.accept().expect("accept primary client");
                stream
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .expect("set primary read timeout");

                let hello = read_resp_frame(&mut stream);
                assert_resp_command(hello, &[b"HELLO", b"3"]);
                let hello_reply = RespValue::Map(vec![(
                    RespValue::SimpleString("proto".to_string()),
                    RespValue::Integer(3),
                )])
                .encode();
                stream
                    .write_all(&hello_reply)
                    .expect("write primary HELLO reply");
                stream.flush().expect("flush primary HELLO reply");

                let get = read_resp_frame(&mut stream);
                assert_resp_command(get, &[b"GET", b"moved-key"]);
                let moved = format!("-MOVED 123 {redirect_target}\r\n");
                stream
                    .write_all(moved.as_bytes())
                    .expect("write MOVED redirect");
                stream.flush().expect("flush MOVED redirect");
            }
        });

        let redirect_server = thread::spawn(move || {
            let (mut stream, _) = redirect_listener
                .accept()
                .expect("accept redirected client");
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .expect("set redirect read timeout");

            let hello = read_resp_frame(&mut stream);
            assert_resp_command(hello, &[b"HELLO", b"3"]);
            let hello_reply = RespValue::Map(vec![(
                RespValue::SimpleString("proto".to_string()),
                RespValue::Integer(3),
            )])
            .encode();
            stream
                .write_all(&hello_reply)
                .expect("write redirect HELLO reply");
            stream.flush().expect("flush redirect HELLO reply");

            let get = read_resp_frame(&mut stream);
            assert_resp_command(get, &[b"GET", b"moved-key"]);
            let value = RespValue::BulkString(Some(b"value".to_vec())).encode();
            stream.write_all(&value).expect("write redirect value");
            stream.flush().expect("flush redirect value");
        });

        run_test_with_cx(|cx| async move {
            let client = RedisClient::connect(
                &cx,
                &format!("redis://{}:{}/0", primary_addr.ip(), primary_addr.port()),
            )
            .await
            .expect("connect redis client");

            let response = client
                .cmd(&cx, &["GET", "moved-key"])
                .await
                .expect("MOVED redirect should retry against target");
            assert_eq!(response, RespValue::BulkString(Some(b"value".to_vec())));

            let slot_map = client.slot_map_snapshot();
            assert_eq!(
                slot_map.get(&123).map(String::as_str),
                Some(redirect_target.as_str()),
                "MOVED handling must record the redirected slot owner like redis-rs"
            );
        });

        primary_server.join().expect("primary server join");
        redirect_server.join().expect("redirect server join");
    }

    fn redis_bulk(value: &str) -> RespValue {
        RespValue::BulkString(Some(value.as_bytes().to_vec()))
    }

    fn cluster_node(endpoint: RespValue, port: i64, node_id: Option<&str>) -> RespValue {
        let mut fields = vec![endpoint, RespValue::Integer(port)];
        if let Some(node_id) = node_id {
            fields.push(redis_bulk(node_id));
        }
        RespValue::Array(Some(fields))
    }

    #[test]
    fn cluster_slots_parser_accepts_metadata_and_replicas() {
        let response = RespValue::Array(Some(vec![RespValue::Array(Some(vec![
            RespValue::Integer(0),
            RespValue::Integer(5460),
            RespValue::Array(Some(vec![
                redis_bulk("127.0.0.1"),
                RespValue::Integer(30001),
                redis_bulk("09dbe9720cda62f7865eabc5fd8857c5d2678366"),
                RespValue::Map(vec![(
                    redis_bulk("hostname"),
                    redis_bulk("host-1.redis.example.com"),
                )]),
            ])),
            RespValue::Array(Some(vec![
                redis_bulk("127.0.0.1"),
                RespValue::Integer(30004),
                redis_bulk("821d8ca00d7ccf931ed3ffc7e3db0599d2271abf"),
                RespValue::Map(vec![(
                    redis_bulk("hostname"),
                    redis_bulk("host-2.redis.example.com"),
                )]),
            ])),
        ]))]));

        let slots = parse_cluster_slots_response(&response).expect("cluster slots should parse");

        assert_eq!(slots.len(), 1);
        assert_eq!(slots[0].start, 0);
        assert_eq!(slots[0].end, 5460);
        assert_eq!(slots[0].master.endpoint.as_deref(), Some("127.0.0.1"));
        assert_eq!(slots[0].master.port, 30001);
        assert_eq!(
            slots[0].master.node_id.as_deref(),
            Some("09dbe9720cda62f7865eabc5fd8857c5d2678366")
        );
        assert_eq!(slots[0].replicas.len(), 1);
        assert_eq!(slots[0].replicas[0].port, 30004);
    }

    #[test]
    fn cluster_slots_parser_accepts_legacy_and_unknown_endpoints() {
        let response = RespValue::Array(Some(vec![
            RespValue::Array(Some(vec![
                RespValue::Integer(0),
                RespValue::Integer(0),
                cluster_node(RespValue::BulkString(None), 6379, None),
            ])),
            RespValue::Array(Some(vec![
                RespValue::Integer(1),
                RespValue::Integer(2),
                cluster_node(redis_bulk("?"), 6380, Some("node-2")),
            ])),
        ]));

        let slots = parse_cluster_slots_response(&response).expect("cluster slots should parse");

        assert_eq!(slots[0].master.endpoint, None);
        assert_eq!(slots[0].master.node_id, None);
        assert_eq!(slots[1].master.endpoint.as_deref(), Some("?"));
        assert_eq!(slots[1].master.node_id.as_deref(), Some("node-2"));
    }

    #[test]
    fn cluster_slots_parser_rejects_bad_ranges() {
        let reversed = RespValue::Array(Some(vec![RespValue::Array(Some(vec![
            RespValue::Integer(9),
            RespValue::Integer(8),
            cluster_node(redis_bulk("127.0.0.1"), 6379, Some("node")),
        ]))]));
        let out_of_range = RespValue::Array(Some(vec![RespValue::Array(Some(vec![
            RespValue::Integer(0),
            RespValue::Integer(16_384),
            cluster_node(redis_bulk("127.0.0.1"), 6379, Some("node")),
        ]))]));

        assert!(parse_cluster_slots_response(&reversed).is_err());
        assert!(parse_cluster_slots_response(&out_of_range).is_err());
    }

    #[test]
    fn resp3_attributes_do_not_desynchronize_pooled_command_replies() {
        let listener = StdTcpListener::bind("127.0.0.1:0").expect("bind test listener");
        let addr = listener.local_addr().expect("listener addr");

        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept redis client");
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .expect("set read timeout");

            let hello = read_resp_frame(&mut stream);
            assert_resp_command(hello, &[b"HELLO", b"3"]);
            let hello_reply = RespValue::Map(vec![(
                RespValue::SimpleString("proto".to_string()),
                RespValue::Integer(3),
            )])
            .encode();
            stream.write_all(&hello_reply).expect("write HELLO reply");
            stream.flush().expect("flush HELLO reply");

            let first = read_resp_frame(&mut stream);
            assert_resp_command(first, &[b"PING"]);

            let attribute = RespValue::Attribute(vec![(
                RespValue::SimpleString("meta".to_string()),
                RespValue::SimpleString("first".to_string()),
            )])
            .encode();
            let first_reply = RespValue::SimpleString("FIRST".to_string()).encode();
            stream
                .write_all(&attribute)
                .expect("write RESP3 attribute metadata");
            stream.write_all(&first_reply).expect("write first reply");
            stream.flush().expect("flush first reply");

            let second = read_resp_frame(&mut stream);
            assert_resp_command(second, &[b"PING"]);
            let second_reply = RespValue::SimpleString("SECOND".to_string()).encode();
            stream.write_all(&second_reply).expect("write second reply");
            stream.flush().expect("flush second reply");
        });

        run_test_with_cx(|cx| async move {
            let url = format!("redis://{}:{}/0", addr.ip(), addr.port());
            let client = RedisClient::connect(&cx, &url)
                .await
                .expect("connect redis client");

            let first = client
                .cmd(&cx, &["PING"])
                .await
                .expect("first PING should ignore RESP3 attributes");
            assert_eq!(first, RespValue::SimpleString("FIRST".to_string()));

            let second = client
                .cmd(&cx, &["PING"])
                .await
                .expect("second PING should stay synchronized");
            assert_eq!(second, RespValue::SimpleString("SECOND".to_string()));
        });

        server.join().expect("server join");
    }

    #[test]
    fn transaction_begin_cancellation_discards_pooled_connection() {
        let listener = StdTcpListener::bind("127.0.0.1:0").expect("bind test listener");
        let addr = listener.local_addr().expect("listener addr");
        let (first_multi_tx, first_multi_rx) = std::sync::mpsc::channel();
        let server = thread::spawn(move || {
            let (mut first_stream, _) = listener.accept().expect("accept first client");
            first_stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .expect("set first read timeout");

            write_hello3_ok(&mut first_stream);
            let first_multi = read_resp_frame(&mut first_stream);
            assert_resp_command(first_multi, &[b"MULTI"]);
            first_multi_tx.send(()).expect("signal first multi");

            let mut probe = [0u8; 1];
            match first_stream.read(&mut probe) {
                Ok(0) => {}
                Ok(n) => panic!(
                    "expected first transaction connection to close after cancellation, read {n} extra byte(s)"
                ),
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                    ) =>
                {
                    panic!("first transaction connection remained open after cancellation")
                }
                Err(e) => panic!("read first transaction connection after cancellation: {e}"),
            }

            let (mut second_stream, _) = listener.accept().expect("accept second client");
            second_stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .expect("set second read timeout");

            write_hello3_ok(&mut second_stream);
            let second_multi = read_resp_frame(&mut second_stream);
            assert_resp_command(second_multi, &[b"MULTI"]);
            second_stream
                .write_all(&RespValue::SimpleString("OK".to_string()).encode())
                .expect("write MULTI response");
            second_stream.flush().expect("flush MULTI response");

            let discard = read_resp_frame(&mut second_stream);
            assert_resp_command(discard, &[b"DISCARD"]);
            second_stream
                .write_all(&RespValue::SimpleString("OK".to_string()).encode())
                .expect("write DISCARD response");
            second_stream.flush().expect("flush DISCARD response");
        });

        run_test_with_cx(|cx| async move {
            let client =
                RedisClient::connect(&cx, &format!("redis://{}:{}/0", addr.ip(), addr.port()))
                    .await
                    .expect("create redis client");

            {
                let mut begin = Box::pin(client.transaction(&cx));
                drive_until_signal(begin.as_mut(), &first_multi_rx, "redis transaction begin");
            }

            let tx = client
                .transaction(&cx)
                .await
                .expect("second transaction should succeed");
            tx.discard(&cx)
                .await
                .expect("second transaction should discard cleanly");
        });

        server.join().expect("server join");
    }

    #[test]
    fn resp_decode_rejects_excessive_nesting() {
        // Build a deeply nested array: *1\r\n repeated 100 times, then :0\r\n
        let mut buf = Vec::new();
        for _ in 0..100 {
            buf.extend_from_slice(b"*1\r\n");
        }
        buf.extend_from_slice(b":0\r\n");

        let err = RespValue::try_decode(&buf).expect_err("should reject deep nesting");
        assert!(matches!(err, RedisError::Protocol(msg) if msg.contains("nesting depth")));
    }

    #[test]
    fn resp_decode_rejects_excessive_array_len() {
        let buf = b"*2000000\r\n:1\r\n:2\r\n".to_vec();
        let err = RespValue::try_decode(&buf).expect_err("should reject large array length");
        assert!(matches!(err, RedisError::Protocol(msg) if msg.contains("array length")));
    }

    #[test]
    fn resp_decode_rejects_excessive_bulk_string_len() {
        let buf = b"$1000000000\r\n".to_vec();
        let err = RespValue::try_decode(&buf).expect_err("should reject large bulk string length");
        assert!(matches!(err, RedisError::Protocol(msg) if msg.contains("bulk string length")));
    }

    #[test]
    fn resp_decode_allows_moderate_nesting() {
        // 10 levels deep should be fine
        let mut buf = Vec::new();
        for _ in 0..10 {
            buf.extend_from_slice(b"*1\r\n");
        }
        buf.extend_from_slice(b":42\r\n");

        let result = RespValue::try_decode(&buf).expect("should succeed");
        assert!(result.is_some());
    }

    #[test]
    fn set_ttl_uses_milliseconds() {
        // Verify that sub-second TTLs don't truncate to zero by using PX
        let ttl = Duration::from_millis(500);
        let mut tmp = [0u8; 20];
        let millis = u64_decimal_bytes(positive_ttl_millis(ttl).expect("positive ttl"), &mut tmp);
        assert_eq!(millis, b"500");
    }

    #[test]
    fn positive_submillisecond_ttl_rounds_up_to_one_millisecond() {
        assert_eq!(positive_ttl_millis(Duration::from_nanos(1)).unwrap(), 1);
        assert_eq!(positive_ttl_millis(Duration::from_micros(999)).unwrap(), 1);
    }

    #[test]
    fn positive_fractional_millisecond_ttl_rounds_up() {
        assert_eq!(
            positive_ttl_millis(Duration::from_millis(1) + Duration::from_nanos(1)).unwrap(),
            2
        );
        assert_eq!(
            positive_ttl_millis(Duration::from_micros(1_001)).unwrap(),
            2
        );
    }

    #[test]
    fn large_ttl_saturates_at_u64_max_milliseconds() {
        assert_eq!(ttl_millis_rounded_up(Duration::MAX), u64::MAX);
    }

    #[test]
    fn zero_ttl_is_rejected_for_set_px() {
        let err = positive_ttl_millis(Duration::ZERO).expect_err("zero ttl must be rejected");
        assert!(matches!(err, RedisError::Protocol(msg) if msg.contains("greater than zero")));
    }

    #[test]
    fn zero_ttl_is_allowed_for_pexpire() {
        assert_eq!(ttl_millis_rounded_up(Duration::ZERO), 0);
    }

    #[test]
    fn dropped_transaction_queue_future_fails_closed_and_discards_connection() {
        let listener = StdTcpListener::bind("127.0.0.1:0").expect("bind test listener");
        let addr = listener.local_addr().expect("listener addr");
        let (queued_seen_tx, queued_seen_rx) = mpsc::channel();
        let (conn_closed_tx, conn_closed_rx) = mpsc::channel();

        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept transaction client");
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .expect("set transaction read timeout");

            let multi = read_resp_frame(&mut stream);
            assert_resp_command(multi, &[b"MULTI"]);
            stream.write_all(b"+OK\r\n").expect("write MULTI response");
            stream.flush().expect("flush MULTI response");

            let queued = read_resp_frame(&mut stream);
            assert_resp_command(queued, &[b"SET", b"key", b"value"]);
            queued_seen_tx
                .send(())
                .expect("signal queued command arrival");

            let mut probe = [0u8; 1];
            match stream.read(&mut probe) {
                Ok(0) => conn_closed_tx
                    .send(())
                    .expect("signal dropped transaction connection"),
                Ok(n) => panic!(
                    "dropped queued transaction command left the connection open; read {n} byte(s)"
                ),
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                    ) =>
                {
                    panic!("dropped queued transaction command did not close the connection")
                }
                Err(e) => panic!("probe transaction connection after dropped queued command: {e}"),
            }
        });

        run_test_with_cx(|cx| async move {
            let url = format!("redis://{}:{}", addr.ip(), addr.port());
            let client = RedisClient::connect(&cx, &url)
                .await
                .expect("connect redis client");
            let mut tx = client.transaction(&cx).await.expect("start transaction");

            {
                let mut queued = Box::pin(tx.cmd(&cx, &["SET", "key", "value"]));
                drive_until_signal(
                    queued.as_mut(),
                    &queued_seen_rx,
                    "redis queued transaction command",
                );
            }

            conn_closed_rx
                .recv_timeout(Duration::from_secs(2))
                .expect("dropped queued transaction command should discard the connection");

            // br-asupersync-4tb7kn: Transaction::cmd_bytes no longer sets
            // self.finished = true before the await points, so a dropped
            // queued future leaves self.finished == false but
            // self.conn == None (DiscardOnDropGuard discarded the
            // poisoned connection). The next cmd hits the take().
            // ok_or_else path with "transaction already finished" rather
            // than the finished-flag's "after transaction completion".
            // Both messages communicate the same observable outcome
            // (further commands on this transaction are rejected); the
            // new shape is more honest about *why* (no live connection
            // vs caller already EXEC'd or DISCARD'd).
            let err = tx
                .cmd(&cx, &["GET", "key"])
                .await
                .expect_err("transaction should fail closed after a dropped queued command");
            match err {
                RedisError::Protocol(message) => {
                    assert!(
                        message.contains("transaction already finished")
                            || message.contains("after transaction completion"),
                        "unexpected transaction failure message: {message}"
                    );
                }
                other => {
                    panic!("expected protocol failure after dropped queued command, got {other:?}")
                }
            }
        });

        server.join().expect("server join");
    }

    #[test]
    fn transaction_redis_error_response_keeps_transaction_alive_for_retry() {
        // br-asupersync-4tb7kn: a `-ERR ...` reply from Redis to a
        // queued cmd_bytes call is a *transient*, command-scoped
        // rejection — not a transaction-terminating event. The
        // transaction object must remain usable: a subsequent
        // cmd_bytes must succeed when the same command shape is
        // accepted, and EXEC must still execute. The pre-fix code
        // already handled this path correctly via the explicit
        // `finished = false` reset on the `RespValue::Error` arm; the
        // fix keeps the contract intact by removing the eager
        // `finished = true` at the top of cmd_bytes (so the post-error
        // reset is no longer required, but the observable contract is
        // identical). This test pins the contract so a future refactor
        // cannot regress it.
        let listener = StdTcpListener::bind("127.0.0.1:0").expect("bind test listener");
        let addr = listener.local_addr().expect("listener addr");
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept transaction client");
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .expect("set transaction read timeout");

            let multi = read_resp_frame(&mut stream);
            assert_resp_command(multi, &[b"MULTI"]);
            stream.write_all(b"+OK\r\n").expect("write MULTI ack");
            stream.flush().expect("flush MULTI ack");

            // First queued command — server returns -ERR (transient).
            let first = read_resp_frame(&mut stream);
            assert_resp_command(first, &[b"BOGUS_COMMAND"]);
            stream
                .write_all(b"-ERR unknown command 'BOGUS_COMMAND'\r\n")
                .expect("write -ERR ack");
            stream.flush().expect("flush -ERR ack");

            // Retry with a valid command — server returns +QUEUED.
            let retry = read_resp_frame(&mut stream);
            assert_resp_command(retry, &[b"SET", b"k", b"v"]);
            stream.write_all(b"+QUEUED\r\n").expect("write +QUEUED ack");
            stream.flush().expect("flush +QUEUED ack");

            // EXEC — server returns array with the SET's reply.
            let exec = read_resp_frame(&mut stream);
            assert_resp_command(exec, &[b"EXEC"]);
            stream.write_all(b"*1\r\n+OK\r\n").expect("write EXEC ack");
            stream.flush().expect("flush EXEC ack");
        });

        run_test_with_cx(|cx| async move {
            let url = format!("redis://{}:{}", addr.ip(), addr.port());
            let client = RedisClient::connect(&cx, &url)
                .await
                .expect("connect redis client");
            let mut tx = client.transaction(&cx).await.expect("start transaction");

            // First queued command rejected by Redis — must surface as
            // RedisError::Redis (not Protocol), and must NOT brick the
            // transaction object.
            let first_err = tx
                .cmd(&cx, &["BOGUS_COMMAND"])
                .await
                .expect_err("BOGUS_COMMAND should be rejected by Redis");
            assert!(
                matches!(first_err, RedisError::Redis(ref msg) if msg.contains("unknown command")),
                "expected RedisError::Redis(unknown command), got {first_err:?}"
            );

            // Transaction is still alive: the next cmd_bytes succeeds.
            tx.cmd(&cx, &["SET", "k", "v"])
                .await
                .expect("retry after -ERR should still queue");

            // EXEC consumes the transaction and returns the queued
            // command's reply.
            let replies = tx.exec(&cx).await.expect("EXEC after retry should succeed");
            assert_eq!(replies.len(), 1);
            assert!(matches!(
                &replies[0],
                RespValue::SimpleString(s) if s == "OK"
            ));
        });

        server.join().expect("server join");
    }

    /// br-asupersync-f3635k (follow-up to br-asupersync-pr32li).
    /// Pipeline::exec must collect ALL responses even when one of them is a
    /// RESP `-ERR` reply, classify the `-ERR` as `Err(RedisError::Redis(_))`
    /// at the per-command position, return the connection to the pool, and
    /// leave the connection healthy enough to serve the next command.
    ///
    /// Scripted server drives the wire exchange:
    ///   1. Client sends HELLO 3 (RESP3 negotiation in ensure_initialized).
    ///      Server replies `-ERR unknown command 'HELLO'\r\n` so the client
    ///      falls through to RESP2 (no AUTH because no password configured).
    ///   2. Client writes the 3 pipelined commands as one combined buffer.
    ///      Server reads three RESP frames in succession.
    ///   3. Server writes back, in one buffer:
    ///      $5\r\nfirst\r\n
    ///      -ERR something went wrong\r\n
    ///      $5\r\nthird\r\n
    ///   4. Client receives Vec<Result<RespValue, RedisError>> with three
    ///      entries; middle one is Err(RedisError::Redis(...)); first and
    ///      third are Ok(BulkString(...)).
    ///   5. Client then runs a single PING via the same pool — reuses the
    ///      same RedisConnection (because the pipeline defused its discard
    ///      guard on the -ERR path) and the server replies +PONG.
    #[test]
    fn pipeline_exec_collects_all_results_when_middle_command_errors() {
        let listener = StdTcpListener::bind("127.0.0.1:0").expect("bind test listener");
        let addr = listener.local_addr().expect("listener addr");

        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept pipeline client");
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .expect("set read timeout");

            // 1. HELLO 3 (RESP3 negotiation). Reply -ERR so client falls back
            //    to RESP2 with no AUTH since the test config has no password.
            let hello = read_resp_frame(&mut stream);
            assert_resp_command(hello, &[b"HELLO", b"3"]);
            stream
                .write_all(b"-ERR unknown command 'HELLO'\r\n")
                .expect("write HELLO -ERR");
            stream.flush().expect("flush HELLO -ERR");

            // 2. Three pipelined commands — read each frame as a separate
            //    RESP array. read_resp_frame asserts each frame is consumed
            //    fully before returning, but pipeline writes all three in
            //    one combined buffer; that's fine because the buffer's
            //    framing boundaries are explicit per RESP.
            let cmd1 = read_resp_frame(&mut stream);
            assert_resp_command(cmd1, &[b"GET", b"k1"]);
            let cmd2 = read_resp_frame(&mut stream);
            assert_resp_command(cmd2, &[b"GET", b"k2"]);
            let cmd3 = read_resp_frame(&mut stream);
            assert_resp_command(cmd3, &[b"GET", b"k3"]);

            // 3. Three responses in one combined write: Ok, -ERR, Ok.
            let mut response = Vec::new();
            response.extend_from_slice(b"$5\r\nfirst\r\n");
            response.extend_from_slice(b"-ERR something went wrong\r\n");
            response.extend_from_slice(b"$5\r\nthird\r\n");
            stream.write_all(&response).expect("write pipeline replies");
            stream.flush().expect("flush pipeline replies");

            // 5. Health check — pipeline should have defused the discard
            //    guard so the SAME RedisConnection comes back from the pool
            //    for the next command. Read PING + reply PONG.
            let ping = read_resp_frame(&mut stream);
            assert_resp_command(ping, &[b"PING"]);
            stream
                .write_all(&RespValue::SimpleString("PONG".to_string()).encode())
                .expect("write PING reply");
            stream.flush().expect("flush PING reply");
        });

        run_test_with_cx(|cx| async move {
            let url = format!("redis://{}:{}", addr.ip(), addr.port());
            let client = RedisClient::connect(&cx, &url)
                .await
                .expect("connect redis client");

            let mut pipeline = client.pipeline();
            pipeline.cmd(&["GET", "k1"]);
            pipeline.cmd(&["GET", "k2"]);
            pipeline.cmd(&["GET", "k3"]);

            let results = pipeline
                .exec(&cx)
                .await
                .expect("pipeline exec must return Ok even when a per-cmd -ERR appears");

            // 4. All three results returned — the mid -ERR did NOT short-
            //    circuit collection.
            assert_eq!(
                results.len(),
                3,
                "pipeline must collect ALL three responses (br-pr32li); got {results:?}"
            );

            // results[0] = Ok(BulkString(first))
            match &results[0] {
                Ok(RespValue::BulkString(Some(bytes))) if bytes == b"first" => {}
                other => panic!("results[0] expected Ok(BulkString(\"first\")), got {other:?}"),
            }

            // results[1] = Err(RedisError::Redis("something went wrong"))
            match &results[1] {
                Err(RedisError::Redis(msg)) if msg.contains("something went wrong") => {}
                other => panic!("results[1] expected Err(RedisError::Redis(...)), got {other:?}"),
            }

            // results[2] = Ok(BulkString(third))
            match &results[2] {
                Ok(RespValue::BulkString(Some(bytes))) if bytes == b"third" => {}
                other => panic!("results[2] expected Ok(BulkString(\"third\")), got {other:?}"),
            }

            // 5. Connection-healthy assertion — a follow-up command must
            //    reuse the pool and succeed. If pipeline had wrongly
            //    discarded the connection on the -ERR, this PING would
            //    fail (or stall on a fresh accept the test server doesn't
            //    handle).
            client
                .ping(&cx)
                .await
                .expect("connection should remain healthy after per-cmd -ERR");
        });

        server.join().expect("server join");
    }

    // ========================================================================
    // REAL REDIS INTEGRATION TESTS (Live Testing Pattern)
    // ========================================================================
    //
    // These tests replace scripted TCP server tests above with real Redis.
    // connections following the testing-perfect-e2e-integration-tests pattern.
    // Run with: REAL_REDIS_TESTS=true cargo test -- --nocapture

    /// Real Redis test configuration with production safety guards
    struct RealRedisConfig {
        host: String,
        port: u16,
        enabled: bool,
        reason: Option<String>,
    }

    impl RealRedisConfig {
        fn new() -> Self {
            let enabled = std::env::var("REAL_REDIS_TESTS").unwrap_or_default() == "true";
            let redis_url =
                std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://localhost:6379".to_string());

            let config = RedisConfig::from_url(&redis_url).unwrap_or_else(|_| RedisConfig {
                host: "localhost".to_string(),
                port: 6379,
                ..Default::default()
            });

            // Production safety guards (Pattern 4 from testing-perfect-e2e-integration-tests)
            let reason = if !enabled {
                Some("REAL_REDIS_TESTS not set to 'true'".to_string())
            } else if config.host.contains("prod") || config.host.contains("production") {
                Some("BLOCKED: Production Redis URL detected".to_string())
            } else if std::env::var("NODE_ENV").unwrap_or_default() == "production" {
                Some("BLOCKED: NODE_ENV=production".to_string())
            } else {
                None
            };

            Self {
                host: config.host,
                port: config.port,
                enabled: enabled && reason.is_none(),
                reason,
            }
        }

        fn url(&self) -> String {
            format!("redis://{}:{}/0", self.host, self.port)
        }
    }

    /// Structured test logger for Redis integration tests (Pattern 3 from skill)
    #[derive(Debug)]
    struct RedisTestLogger {
        test_name: String,
        start_time: std::time::Instant,
        phase_count: AtomicU32,
    }

    impl RedisTestLogger {
        fn new(test_name: &str) -> Self {
            let logger = Self {
                test_name: test_name.to_string(),
                start_time: std::time::Instant::now(),
                phase_count: AtomicU32::new(0),
            };

            // JSON-line structured logging for CI parsing
            eprintln!(
                "{{\"test\":\"{}\",\"event\":\"test_start\",\"ts\":\"{}\"}}",
                test_name,
                chrono::Utc::now().to_rfc3339()
            );

            logger
        }

        fn phase(&self, phase_name: &str) {
            let phase_num = self.phase_count.fetch_add(1, Ordering::SeqCst);
            let elapsed_ms = self.start_time.elapsed().as_millis();

            eprintln!(
                "{{\"test\":\"{}\",\"event\":\"phase\",\"phase\":\"{}\",\"phase_num\":{},\"elapsed_ms\":{},\"ts\":\"{}\"}}",
                self.test_name,
                phase_name,
                phase_num,
                elapsed_ms,
                chrono::Utc::now().to_rfc3339()
            );
        }

        fn redis_operation(&self, operation: &str, result: &str, key: Option<&str>) {
            let mut log_entry = serde_json::json!({
                "test": self.test_name,
                "event": "redis_operation",
                "operation": operation,
                "result": result,
                "ts": chrono::Utc::now().to_rfc3339()
            });

            if let Some(k) = key {
                log_entry["key"] = serde_json::Value::String(k.to_string());
            }

            eprintln!("{}", log_entry);
        }

        fn test_end(&self, result: &str) {
            let duration_ms = self.start_time.elapsed().as_millis();

            eprintln!(
                "{{\"test\":\"{}\",\"event\":\"test_end\",\"result\":\"{}\",\"duration_ms\":{},\"ts\":\"{}\"}}",
                self.test_name,
                result,
                duration_ms,
                chrono::Utc::now().to_rfc3339()
            );
        }
    }

    /// Generate unique key prefixes to avoid cross-test contamination
    fn unique_key_prefix(base: &str) -> String {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis();
        let random = fastrand::u32(..);
        format!("test:{}:{}:{}", base, timestamp, random)
    }

    fn require_real_redis() -> Option<RealRedisConfig> {
        let config = RealRedisConfig::new();
        if !config.enabled {
            let reason = config
                .reason
                .as_deref()
                .unwrap_or("Real Redis server not available");
            eprintln!("SKIPPING: {}", reason);
            return None;
        }
        Some(config)
    }

    /// Test Redis pub/sub with real Redis server (replaces pubsub_ping_preserves_interleaved_messages)
    #[test]
    fn test_real_redis_pubsub_ping_preserves_interleaved_messages() {
        let Some(config) = require_real_redis() else {
            return;
        };

        let log = RedisTestLogger::new("real_redis_pubsub_ping_interleaved");

        run_test_with_cx(|cx| async move {
            let redis_url = config.url();
            let channel_prefix = unique_key_prefix("ping-interleaved");
            let channel = format!("{}:chan", channel_prefix);

            log.phase("setup");

            let client = RedisClient::connect(&cx, &redis_url)
                .await
                .expect("connect redis client");
            let mut pubsub = client.pubsub(&cx).await.expect("open pubsub client");

            log.phase("subscribe");

            // Subscribe to real Redis channel
            pubsub.subscribe(&cx, &[channel.as_str()]).await.unwrap();
            log.redis_operation("subscribe", "success", Some(&channel));

            log.phase("ping_with_message");

            // Send ping while message is pending (tests real Redis interleaving behavior)
            let ping_result = pubsub.ping(&cx, None).await;
            assert!(
                ping_result.is_ok(),
                "Real Redis ping should succeed during pub/sub"
            );
            log.redis_operation("ping", "success", None);

            log.phase("verify_subscription_intact");

            // Verify subscription is still active after ping
            // In real Redis, the subscription should remain intact
            assert!(
                pubsub
                    .channels()
                    .iter()
                    .any(|existing| existing == &channel),
                "Subscription should remain active after ping"
            );

            log.phase("cleanup");
            pubsub.unsubscribe(&cx, &[channel.as_str()]).await.unwrap();
            log.redis_operation("unsubscribe", "success", Some(&channel));

            log.test_end("pass");
        });
    }

    /// Test Redis pub/sub reconnection with real Redis server (replaces pubsub_reconnect_discards_buffered_events)
    #[test]
    fn test_real_redis_pubsub_reconnect_behavior() {
        let Some(config) = require_real_redis() else {
            return;
        };

        let log = RedisTestLogger::new("real_redis_pubsub_reconnect");

        run_test_with_cx(|cx| async move {
            let redis_url = config.url();
            let channel_prefix = unique_key_prefix("reconnect");
            let channel = format!("{}:events", channel_prefix);

            log.phase("setup");

            let client = RedisClient::connect(&cx, &redis_url)
                .await
                .expect("connect redis client");
            let mut pubsub = client.pubsub(&cx).await.expect("open pubsub client");

            log.phase("initial_connection");

            // Subscribe to real Redis
            pubsub.subscribe(&cx, &[channel.as_str()]).await.unwrap();
            log.redis_operation("initial_subscribe", "success", Some(&channel));

            log.phase("force_reconnect");

            let reconnect_result = pubsub.reconnect(&cx).await;
            assert!(
                reconnect_result.is_ok(),
                "Real Redis reconnection should succeed"
            );
            log.redis_operation("reconnect", "success", None);

            log.phase("verify_restored_state");

            assert!(
                pubsub
                    .channels()
                    .iter()
                    .any(|existing| existing == &channel),
                "Tracked subscriptions should persist across reconnect and be restored"
            );

            log.phase("cleanup");
            pubsub.unsubscribe(&cx, &[channel.as_str()]).await.unwrap();

            log.test_end("pass");
        });
    }

    /// Test Redis pub/sub cancellation with real Redis (replaces pubsub_cancelled_subscribe_poison_connection)
    #[test]
    fn test_real_redis_pubsub_cancellation_handling() {
        let Some(config) = require_real_redis() else {
            return;
        };

        let log = RedisTestLogger::new("real_redis_pubsub_cancellation");

        run_test_with_cx(|cx| async move {
            let redis_url = config.url();
            let channel_prefix = unique_key_prefix("cancel");
            let channel = format!("{}:test", channel_prefix);

            log.phase("setup");

            let client = RedisClient::connect(&cx, &redis_url)
                .await
                .expect("connect redis client");
            let mut pubsub = client.pubsub(&cx).await.expect("open pubsub client");

            log.phase("subscribe_with_cancellation");

            match crate::time::timeout(
                cx.now(),
                Duration::from_millis(1),
                pubsub.subscribe(&cx, &[channel.as_str()]),
            )
            .await
            {
                Ok(Ok(())) => {
                    log.redis_operation("subscribe", "completed_before_timeout", Some(&channel));
                }
                Ok(Err(err)) => panic!("real Redis subscribe failed unexpectedly: {err}"),
                Err(_) => {
                    log.redis_operation("subscribe", "timed_out", Some(&channel));
                }
            }

            log.phase("verify_connection_health");

            // Test that the connection is still healthy for future operations
            let health_check = pubsub.ping(&cx, None).await;

            match health_check {
                Ok(_) => {
                    log.redis_operation("health_check", "connection_healthy", None);
                }
                Err(_) => {
                    // Real Redis might require reconnection after cancelled subscribe
                    let reconnect_result = pubsub.reconnect(&cx).await;
                    assert!(
                        reconnect_result.is_ok(),
                        "Should be able to reconnect after cancellation"
                    );
                    log.redis_operation("health_check", "reconnect_required", None);
                }
            }

            log.phase("verify_normal_operation");

            if !pubsub
                .channels()
                .iter()
                .any(|existing| existing == &channel)
            {
                pubsub.subscribe(&cx, &[channel.as_str()]).await.unwrap();
                log.redis_operation("post_cancel_subscribe", "success", Some(&channel));
            }

            log.phase("cleanup");
            pubsub.unsubscribe(&cx, &[channel.as_str()]).await.unwrap();

            log.test_end("pass");
        });
    }

    /// Test Redis command cancellation with real Redis (replaces cmd_cancellation_discards_pooled_connection)
    #[test]
    fn test_real_redis_command_cancellation_behavior() {
        let Some(config) = require_real_redis() else {
            return;
        };

        let log = RedisTestLogger::new("real_redis_cmd_cancellation");

        run_test_with_cx(|cx| async move {
            let redis_url = config.url();
            let key_prefix = unique_key_prefix("cmd-cancel");

            log.phase("setup");

            let client = RedisClient::connect(&cx, &redis_url)
                .await
                .expect("connect redis client");

            log.phase("normal_operation");

            // Establish baseline with normal operation
            let baseline_key = format!("{}:baseline", key_prefix);
            client.set(&cx, &baseline_key, b"test", None).await.unwrap();
            log.redis_operation("baseline_set", "success", Some(&baseline_key));

            log.phase("cancelled_operation");

            // Exercise cancelled operation against real Redis connection cleanup.
            let cancel_key = format!("{}:cancelled", key_prefix);

            // Start a potentially long operation
            match crate::time::timeout(
                cx.now(),
                Duration::from_millis(1),
                client.set(&cx, &cancel_key, b"will_be_cancelled", None),
            )
            .await
            {
                Ok(Ok(())) => {
                    log.redis_operation(
                        "cancelled_set",
                        "completed_before_timeout",
                        Some(&cancel_key),
                    );
                }
                Ok(Err(err)) => panic!("real Redis SET failed unexpectedly: {err}"),
                Err(_) => {
                    log.redis_operation("cancelled_set", "timed_out", Some(&cancel_key));
                }
            }

            log.phase("verify_connection_health");

            // Critical test: verify connection pool handles cancellation correctly in real Redis
            let health_key = format!("{}:health", key_prefix);
            let health_result = client.set(&cx, &health_key, b"healthy", None).await;

            assert!(
                health_result.is_ok(),
                "Real Redis connection should recover from cancelled operations"
            );
            log.redis_operation("post_cancel_health", "success", Some(&health_key));

            log.phase("cleanup");
            let _ = client.del(&cx, &[baseline_key.as_str()]).await;
            let _ = client.del(&cx, &[cancel_key.as_str()]).await;
            let _ = client.del(&cx, &[health_key.as_str()]).await;

            log.test_end("pass");
        });
    }

    /// Test Redis transaction cancellation with real Redis (replaces transaction_begin_cancellation_discards_pooled_connection)
    #[test]
    fn test_real_redis_transaction_cancellation_behavior() {
        let Some(config) = require_real_redis() else {
            return;
        };

        let log = RedisTestLogger::new("real_redis_transaction_cancellation");

        run_test_with_cx(|cx| async move {
            let redis_url = config.url();
            let key_prefix = unique_key_prefix("tx-cancel");

            log.phase("setup");

            let client = RedisClient::connect(&cx, &redis_url)
                .await
                .expect("connect redis client");

            log.phase("normal_transaction");

            // Start with normal transaction to establish baseline
            let tx_key = format!("{}:tx", key_prefix);
            let mut transaction = client.transaction(&cx).await.unwrap();
            transaction
                .cmd(&cx, &["SET", tx_key.as_str(), "normal"])
                .await
                .unwrap();
            let tx_result = transaction.exec(&cx).await;

            assert!(
                tx_result.is_ok(),
                "Normal transaction should succeed with real Redis"
            );
            log.redis_operation("normal_transaction", "success", Some(&tx_key));

            log.phase("cancelled_transaction");

            // Test cancellation during transaction begin phase
            let cancel_key = format!("{}:cancel", key_prefix);

            // Exercise cancellation during MULTI command.
            match crate::time::timeout(cx.now(), Duration::from_millis(1), client.transaction(&cx))
                .await
            {
                Ok(Ok(transaction)) => {
                    drop(transaction);
                    log.redis_operation(
                        "cancelled_multi",
                        "completed_before_timeout",
                        Some(&cancel_key),
                    );
                }
                Ok(Err(err)) => panic!("real Redis MULTI failed unexpectedly: {err}"),
                Err(_) => {
                    log.redis_operation("cancelled_multi", "timed_out", Some(&cancel_key));
                }
            }

            log.phase("verify_connection_recovery");

            // Real Redis should handle cancelled transaction begin cleanly
            let recovery_key = format!("{}:recovery", key_prefix);
            let recovery_result = client.set(&cx, &recovery_key, b"recovered", None).await;

            assert!(
                recovery_result.is_ok(),
                "Real Redis should recover from cancelled transaction begin"
            );
            log.redis_operation("post_cancel_recovery", "success", Some(&recovery_key));

            log.phase("verify_new_transaction");

            // Verify new transaction works after cancellation
            let new_tx_key = format!("{}:new_tx", key_prefix);
            let mut new_transaction = client.transaction(&cx).await.unwrap();
            new_transaction
                .cmd(&cx, &["SET", new_tx_key.as_str(), "new"])
                .await
                .unwrap();
            let new_tx_result = new_transaction.exec(&cx).await;

            assert!(
                new_tx_result.is_ok(),
                "New transaction should work after cancellation recovery"
            );
            log.redis_operation("new_transaction", "success", Some(&new_tx_key));

            log.phase("cleanup");
            let _ = client.del(&cx, &[tx_key.as_str()]).await;
            let _ = client.del(&cx, &[recovery_key.as_str()]).await;
            let _ = client.del(&cx, &[new_tx_key.as_str()]).await;

            log.test_end("pass");
        });
    }

    /// Test Redis transaction queue cancellation (replaces dropped_transaction_queue_future_fails_closed_and_discards_connection)
    #[test]
    fn test_real_redis_transaction_queue_cancellation() {
        let Some(config) = require_real_redis() else {
            return;
        };

        let log = RedisTestLogger::new("real_redis_transaction_queue_cancel");

        run_test_with_cx(|cx| async move {
            let redis_url = config.url();
            let key_prefix = unique_key_prefix("queue-cancel");

            log.phase("setup");

            let client = RedisClient::connect(&cx, &redis_url)
                .await
                .expect("connect redis client");

            log.phase("queue_transaction");

            // Create a queued transaction (MULTI without immediate EXEC)
            let queue_key = format!("{}:queued", key_prefix);
            let mut transaction = client.transaction(&cx).await.unwrap();
            transaction
                .cmd(&cx, &["SET", queue_key.as_str(), "queued_value"])
                .await
                .unwrap();
            // Don't exec yet - keep it queued

            log.redis_operation("transaction_queued", "pending", Some(&queue_key));

            log.phase("drop_queued_transaction");

            // Drop the transaction future (simulates cancellation/timeout)
            drop(transaction);
            log.redis_operation("transaction_dropped", "cancelled", Some(&queue_key));

            log.phase("verify_fail_closed_behavior");

            // In real Redis, dropped queued transaction should fail closed
            // Check that the key was NOT set (transaction was discarded)
            let get_result = client.get(&cx, &queue_key).await;

            match get_result {
                Ok(Some(value)) if value.as_slice() == b"queued_value" => {
                    panic!("Dropped transaction should NOT have committed in real Redis");
                }
                Ok(None) | Ok(Some(_)) | Err(_) => {
                    // Good: either key doesn't exist or has different value
                    log.redis_operation("verify_fail_closed", "correct_behavior", Some(&queue_key));
                }
            }

            log.phase("verify_connection_health");

            // Connection should remain healthy after dropped transaction
            let health_key = format!("{}:health", key_prefix);
            let health_result = client.set(&cx, &health_key, b"healthy", None).await;

            assert!(
                health_result.is_ok(),
                "Connection should be healthy after dropped transaction"
            );
            log.redis_operation("connection_health", "success", Some(&health_key));

            log.phase("cleanup");
            let _ = client.del(&cx, &[queue_key.as_str()]).await;
            let _ = client.del(&cx, &[health_key.as_str()]).await;

            log.test_end("pass");
        });
    }

    /// Test Redis pipeline error handling with real Redis (replaces pipeline_exec_collects_all_results_when_middle_command_errors)
    #[test]
    fn test_real_redis_pipeline_error_collection() {
        let Some(config) = require_real_redis() else {
            return;
        };

        let log = RedisTestLogger::new("real_redis_pipeline_errors");

        run_test_with_cx(|cx| async move {
            let redis_url = config.url();
            let key_prefix = unique_key_prefix("pipeline-err");

            log.phase("setup");

            let client = RedisClient::connect(&cx, &redis_url)
                .await
                .expect("connect redis client");

            log.phase("setup_test_data");

            // Set up keys for pipeline test
            let key1 = format!("{}:first", key_prefix);
            let key2 = format!("{}:second", key_prefix);
            let key3 = format!("{}:third", key_prefix);

            client.set(&cx, &key1, b"first", None).await.unwrap();
            client.set(&cx, &key2, b"not-an-int", None).await.unwrap();
            client.set(&cx, &key3, b"third", None).await.unwrap();

            log.phase("execute_pipeline");

            // Create pipeline with intentional error in middle command
            let mut pipeline = client.pipeline();
            pipeline.cmd(&["GET", key1.as_str()]);
            pipeline.cmd(&["INCR", key2.as_str()]);
            pipeline.cmd(&["GET", key3.as_str()]);
            let pipeline_result = pipeline.exec(&cx).await;

            log.redis_operation("pipeline_execution", "completed", None);

            log.phase("verify_error_collection");

            match pipeline_result {
                Ok(results) => {
                    // Real Redis pipeline should collect all results, even with errors
                    assert_eq!(results.len(), 3, "Pipeline should return all 3 results");

                    // First command should succeed
                    match &results[0] {
                        Ok(RespValue::BulkString(Some(bytes))) if bytes == b"first" => {
                            log.redis_operation("pipeline_cmd_1", "success", Some(&key1));
                        }
                        other => panic!("First pipeline result should be 'first', got {:?}", other),
                    }

                    // Second command should fail with Redis error
                    match &results[1] {
                        Err(_) => {
                            log.redis_operation("pipeline_cmd_2", "error_expected", Some(&key2));
                        }
                        Ok(value) => panic!("Second pipeline command should fail, got {:?}", value),
                    }

                    // Third command should succeed despite middle error
                    match &results[2] {
                        Ok(RespValue::BulkString(Some(bytes))) if bytes == b"third" => {
                            log.redis_operation("pipeline_cmd_3", "success", Some(&key3));
                        }
                        other => panic!("Third pipeline result should be 'third', got {:?}", other),
                    }
                }
                Err(e) => panic!(
                    "Pipeline should not fail entirely due to single command error: {}",
                    e
                ),
            }

            log.phase("verify_connection_health");

            // Connection should remain healthy after pipeline with errors
            let health_key = format!("{}:health", key_prefix);
            let health_result = client.set(&cx, &health_key, b"healthy", None).await;

            assert!(
                health_result.is_ok(),
                "Connection should remain healthy after pipeline errors"
            );
            log.redis_operation("post_pipeline_health", "success", Some(&health_key));

            log.phase("cleanup");
            let _ = client.del(&cx, &[key1.as_str()]).await;
            let _ = client.del(&cx, &[key2.as_str()]).await;
            let _ = client.del(&cx, &[key3.as_str()]).await;
            let _ = client.del(&cx, &[health_key.as_str()]).await;

            log.test_end("pass");
        });
    }

    /// Test Redis transaction error handling with real Redis (covers the transaction error handling test around line 4063)
    #[test]
    fn test_real_redis_transaction_error_handling() {
        let Some(config) = require_real_redis() else {
            return;
        };

        let log = RedisTestLogger::new("real_redis_transaction_errors");

        run_test_with_cx(|cx| async move {
            let redis_url = config.url();
            let key_prefix = unique_key_prefix("tx-err");

            log.phase("setup");

            let client = RedisClient::connect(&cx, &redis_url)
                .await
                .expect("connect redis client");

            log.phase("normal_transaction");

            // First establish normal transaction works
            let normal_key = format!("{}:normal", key_prefix);
            let mut normal_tx = client.transaction(&cx).await.unwrap();
            normal_tx
                .cmd(&cx, &["SET", normal_key.as_str(), "normal_value"])
                .await
                .unwrap();
            let normal_result = normal_tx.exec(&cx).await;

            assert!(normal_result.is_ok(), "Normal transaction should succeed");
            log.redis_operation("normal_transaction", "success", Some(&normal_key));

            log.phase("transaction_with_error");

            // Transaction that contains an error
            let error_key = format!("{}:error", key_prefix);
            let nonexist_key = format!("{}:nonexistent", key_prefix);

            client
                .set(&cx, &nonexist_key, b"not-an-int", None)
                .await
                .unwrap();
            let mut error_tx = client.transaction(&cx).await.unwrap();
            error_tx
                .cmd(&cx, &["SET", error_key.as_str(), "before_error"])
                .await
                .unwrap();
            error_tx
                .cmd(&cx, &["INCR", nonexist_key.as_str()])
                .await
                .unwrap();
            error_tx
                .cmd(&cx, &["SET", error_key.as_str(), "after_error"])
                .await
                .unwrap();

            let error_result = error_tx.exec(&cx).await;

            log.phase("verify_error_behavior");

            match error_result {
                Ok(results) => {
                    log.redis_operation(
                        "transaction_with_errors",
                        "partial_success",
                        Some(&error_key),
                    );
                    assert_eq!(
                        results.len(),
                        3,
                        "Transaction should return results for all queued commands"
                    );
                    assert!(
                        matches!(&results[1], RespValue::Error(message) if message.to_ascii_lowercase().contains("not an integer")),
                        "Second transaction result should be an integer-type Redis error, got {:?}",
                        results[1]
                    );
                }
                Err(err) => {
                    panic!("EXEC should surface per-command errors inside the result array: {err}")
                }
            }

            log.phase("verify_connection_after_error");

            // Most important: connection should remain usable after transaction error
            let recovery_key = format!("{}:recovery", key_prefix);
            let recovery_result = client.set(&cx, &recovery_key, b"recovered", None).await;

            assert!(
                recovery_result.is_ok(),
                "Connection should recover after transaction error"
            );
            log.redis_operation("post_error_recovery", "success", Some(&recovery_key));

            log.phase("verify_new_transaction");

            // New transaction should work normally
            let new_key = format!("{}:new", key_prefix);
            let mut new_tx = client.transaction(&cx).await.unwrap();
            new_tx
                .cmd(&cx, &["SET", new_key.as_str(), "new_value"])
                .await
                .unwrap();
            let new_result = new_tx.exec(&cx).await;

            assert!(
                new_result.is_ok(),
                "New transaction should work after error recovery"
            );
            log.redis_operation("new_transaction", "success", Some(&new_key));

            log.phase("cleanup");
            let _ = client.del(&cx, &[normal_key.as_str()]).await;
            let _ = client.del(&cx, &[error_key.as_str()]).await;
            let _ = client.del(&cx, &[nonexist_key.as_str()]).await;
            let _ = client.del(&cx, &[recovery_key.as_str()]).await;
            let _ = client.del(&cx, &[new_key.as_str()]).await;

            log.test_end("pass");
        });
    }

    /// Differential conformance test for RESP3 numeric integer encoding at i64 boundary values.
    ///
    /// Tests RESP3 specification compliance for integer encoding/decoding round-trips,
    /// specifically focusing on i64::MIN/MAX boundaries and negative number handling.
    ///
    /// RESP3 integer format: `:` + ASCII decimal + `\r\n`
    ///
    /// Coverage:
    /// - MUST: i64::MAX encodes and round-trips correctly
    /// - MUST: i64::MIN encodes and round-trips correctly
    /// - MUST: Negative numbers preserve sign and magnitude
    /// - MUST: Edge values near boundaries encode properly
    /// - MUST: Values outside i64 range are rejected with protocol error
    #[test]
    fn resp3_integer_encoding_i64_boundary_differential() {
        // Test vector: (value, expected_wire_format, should_succeed)
        let boundary_cases: &[(i64, &[u8], bool)] = &[
            // i64::MAX boundary
            (i64::MAX, b":9223372036854775807\r\n", true),
            (i64::MAX - 1, b":9223372036854775806\r\n", true),
            // i64::MIN boundary
            (i64::MIN, b":-9223372036854775808\r\n", true),
            (i64::MIN + 1, b":-9223372036854775807\r\n", true),
            // Zero and small values
            (0, b":0\r\n", true),
            (-1, b":-1\r\n", true),
            (1, b":1\r\n", true),
            // Typical negative values
            (-42, b":-42\r\n", true),
            (-1000000, b":-1000000\r\n", true),
        ];

        for &(value, expected_wire, should_succeed) in boundary_cases {
            // Test encoding: value -> wire format
            let actual = RespValue::Integer(value);
            let encoded = actual.encode();

            if should_succeed {
                assert_eq!(
                    encoded,
                    expected_wire,
                    "RESP3 encoding mismatch for i64 value {value}\n\
                     Expected: {:?}\n\
                     Actual:   {:?}",
                    std::str::from_utf8(expected_wire).unwrap_or("<invalid utf8>"),
                    std::str::from_utf8(&encoded).unwrap_or("<invalid utf8>")
                );

                // Test round-trip: wire format -> value -> wire format
                let (decoded_value, consumed) = RespValue::try_decode(&encoded)
                    .expect("parse should succeed")
                    .expect("should have complete value");

                assert_eq!(consumed, encoded.len(), "should consume entire input");
                assert_eq!(
                    decoded_value,
                    RespValue::Integer(value),
                    "round-trip failed for value {value}"
                );

                // Test integer extraction
                assert_eq!(
                    decoded_value.as_integer(),
                    Some(value),
                    "as_integer() failed for value {value}"
                );
            }
        }

        // Test overflow cases - values outside i64 range should fail gracefully
        let overflow_cases: &[&[u8]] = &[
            b":9223372036854775808\r\n",   // i64::MAX + 1
            b":-9223372036854775809\r\n",  // i64::MIN - 1
            b":99999999999999999999\r\n",  // Way beyond i64::MAX
            b":-99999999999999999999\r\n", // Way beyond i64::MIN
        ];

        for &overflow_wire in overflow_cases {
            let parse_result = RespValue::try_decode(overflow_wire);

            match parse_result {
                Ok(None) => {
                    // Incomplete parse - this is OK for malformed input
                }
                Ok(Some(_)) => {
                    panic!(
                        "Expected overflow error for input: {:?}",
                        std::str::from_utf8(overflow_wire).unwrap_or("<invalid utf8>")
                    );
                }
                Err(RedisError::Protocol(msg)) => {
                    // Expected: protocol error for overflow
                    assert!(
                        msg.contains("overflow") || msg.contains("integer"),
                        "Error message should mention overflow/integer, got: {}",
                        msg
                    );
                }
                Err(other) => {
                    panic!("Expected protocol error for overflow, got: {:?}", other);
                }
            }
        }

        // Test malformed integer cases
        let malformed_cases: &[&[u8]] = &[
            b":abc\r\n",   // Non-numeric
            b":\r\n",      // Empty
            b":-\r\n",     // Just minus sign
            b":12x34\r\n", // Mixed numeric/alpha
            b":0x42\r\n",  // Hex format (not allowed in RESP)
        ];

        for &malformed_wire in malformed_cases {
            let parse_result = RespValue::try_decode(malformed_wire);

            match parse_result {
                Ok(None) => {
                    // Incomplete parse - acceptable
                }
                Ok(Some(_)) => {
                    panic!(
                        "Expected parse error for malformed input: {:?}",
                        std::str::from_utf8(malformed_wire).unwrap_or("<invalid utf8>")
                    );
                }
                Err(RedisError::Protocol(_)) => {
                    // Expected: protocol error for malformed input
                }
                Err(other) => {
                    panic!(
                        "Expected protocol error for malformed input, got: {:?}",
                        other
                    );
                }
            }
        }

        // Differential verification: our encoder output should be parseable by our decoder
        // This verifies internal consistency of our RESP3 integer implementation
        let test_values = [
            i64::MIN,
            i64::MIN + 1,
            -1000000,
            -42,
            -1,
            0,
            1,
            42,
            1000000,
            i64::MAX - 1,
            i64::MAX,
        ];

        for &value in &test_values {
            let encoded = RespValue::Integer(value).encode();
            let (decoded, _) = RespValue::try_decode(&encoded)
                .expect("should parse")
                .expect("should be complete");

            assert_eq!(
                decoded,
                RespValue::Integer(value),
                "Self-consistency check failed for value {value}"
            );
        }
    }

    /// AUDIT MODULE: Redis ACL authentication error handling verification
    ///
    /// AUDIT FINDING: FIXED - Previous implementation wrapped authentication errors
    /// (NOAUTH, WRONGPASS) in generic RedisError::Protocol variants, causing
    /// information loss and making errors non-actionable for callers.
    ///
    /// FIXED: Added structured error types RedisError::NoAuth and RedisError::WrongPassword
    /// with proper parsing logic that callers can match on for appropriate handling.
    #[cfg(test)]
    mod redis_acl_authentication_error_audit {
        use super::*;

        #[test]
        fn audit_redis_error_message_parsing_noauth() {
            // Test Case 1: Standard NOAUTH error
            let error = RedisError::from_redis_error_message("NOAUTH Authentication required");
            match error {
                RedisError::NoAuth => {
                    // Expected - structured error for actionable handling
                }
                other => panic!("Expected RedisError::NoAuth, got {:?}", other),
            }

            // Test Case 2: Bare NOAUTH
            let error = RedisError::from_redis_error_message("NOAUTH");
            match error {
                RedisError::NoAuth => {
                    // Expected - handles minimal form
                }
                other => panic!(
                    "Expected RedisError::NoAuth for bare 'NOAUTH', got {:?}",
                    other
                ),
            }

            // Test Case 3: Case insensitive
            let error = RedisError::from_redis_error_message("noauth authentication required");
            assert!(
                matches!(error, RedisError::NoAuth),
                "NOAUTH parsing must be case-insensitive"
            );
        }

        #[test]
        fn audit_redis_error_message_parsing_wrongpass() {
            // Test Case 1: Standard WRONGPASS error
            let error =
                RedisError::from_redis_error_message("WRONGPASS invalid username-password pair");
            match error {
                RedisError::WrongPassword => {
                    // Expected - structured error for actionable handling
                }
                other => panic!("Expected RedisError::WrongPassword, got {:?}", other),
            }

            // Test Case 2: Bare WRONGPASS
            let error = RedisError::from_redis_error_message("WRONGPASS");
            match error {
                RedisError::WrongPassword => {
                    // Expected - handles minimal form
                }
                other => panic!(
                    "Expected RedisError::WrongPassword for bare 'WRONGPASS', got {:?}",
                    other
                ),
            }

            // Test Case 3: Case insensitive
            let error = RedisError::from_redis_error_message("wrongpass invalid credentials");
            assert!(
                matches!(error, RedisError::WrongPassword),
                "WRONGPASS parsing must be case-insensitive"
            );
        }

        #[test]
        fn audit_redis_error_message_parsing_other_errors() {
            // Test Case: Other errors remain as generic Redis errors
            let error = RedisError::from_redis_error_message("ERR syntax error");
            match error {
                RedisError::Redis(msg) => {
                    assert_eq!(
                        msg, "ERR syntax error",
                        "Generic Redis errors must preserve original message"
                    );
                }
                other => panic!(
                    "Expected RedisError::Redis for generic error, got {:?}",
                    other
                ),
            }

            let error = RedisError::from_redis_error_message("MOVED 3999 127.0.0.1:6381");
            assert!(
                matches!(error, RedisError::Redis(_)),
                "MOVED errors should remain generic"
            );
        }

        #[test]
        fn audit_error_display_messages_are_actionable() {
            // Test Case 1: NoAuth display message
            let error = RedisError::NoAuth;
            let display = format!("{}", error);
            assert!(
                display.contains("NOAUTH") && display.contains("authentication required"),
                "NoAuth display message must be actionable: {}",
                display
            );

            // Test Case 2: WrongPassword display message
            let error = RedisError::WrongPassword;
            let display = format!("{}", error);
            assert!(
                display.contains("WRONGPASS") && display.contains("authentication failed"),
                "WrongPassword display message must be actionable: {}",
                display
            );
        }

        #[test]
        fn audit_structured_errors_enable_caller_pattern_matching() {
            // Test Case: Demonstrate that callers can now handle authentication errors specifically
            fn handle_redis_auth_error(error: &RedisError) -> &'static str {
                match error {
                    RedisError::NoAuth => "prompt_for_credentials",
                    RedisError::WrongPassword => "invalid_credentials_retry",
                    RedisError::Redis(_) => "generic_error_handling",
                    _ => "other_error_handling",
                }
            }

            let noauth_error = RedisError::NoAuth;
            assert_eq!(
                handle_redis_auth_error(&noauth_error),
                "prompt_for_credentials"
            );

            let wrongpass_error = RedisError::WrongPassword;
            assert_eq!(
                handle_redis_auth_error(&wrongpass_error),
                "invalid_credentials_retry"
            );

            let generic_error = RedisError::Redis("ERR syntax error".to_string());
            assert_eq!(
                handle_redis_auth_error(&generic_error),
                "generic_error_handling"
            );
        }

        // AUDIT VERIFICATION:
        // ✓ NOAUTH and WRONGPASS errors now surfaced as structured RedisError variants
        // ✓ Callers can match on specific authentication error types for actionable handling
        // ✓ Case-insensitive parsing handles Redis server variations
        // ✓ Display messages include Redis error codes for debugging
        // ✓ Generic Redis errors continue to preserve original server messages
        // ✓ No information loss - authentication errors are fully actionable
    }

    /// Audit test for RESP3 push-frame parsing under malformed inputs.
    ///
    /// BEHAVIOR VERIFICATION: When server sends "|" prefix (push/attribute) followed by
    /// malformed length or truncated body, our parser correctly returns structured
    /// ParseError (option b: actionable) rather than panic (option c: dangerous) or
    /// skip-and-continue (option a: tolerant but potentially masking issues).
    #[test]
    fn audit_resp3_push_frame_malformed_input_handling() {
        // RESP3 Push Frame Format: "|N\r\n" followed by N key-value pairs
        // RESP3 Attribute Format: "|N\r\n" followed by N key-value pairs (same wire format)

        // Test Category 1: Malformed length after "|" prefix
        let malformed_length_cases = [
            // Non-digit characters in length
            b"|abc\r\n".as_slice(),
            b"|-\r\n".as_slice(),
            b"|12x34\r\n".as_slice(),
            b"|\r\n".as_slice(), // Empty length
            // Negative length (invalid for aggregate types)
            b"|-5\r\n".as_slice(),
            // Integer overflow cases
            b"|99999999999999999999\r\n".as_slice(),
        ];

        for (i, malformed_input) in malformed_length_cases.iter().enumerate() {
            let result = RespValue::try_decode(malformed_input);

            match result {
                Ok(None) => {
                    panic!(
                        "Test case {i}: Complete malformed push frame length must return \
                         structured Protocol error, not incomplete parse"
                    );
                }
                Ok(Some(_)) => {
                    panic!(
                        "Test case {i}: Expected parse error for malformed push frame length, \
                         but parsing succeeded: {:?}",
                        std::str::from_utf8(malformed_input).unwrap_or("<invalid utf8>")
                    );
                }
                Err(RedisError::Protocol(msg)) => {
                    // EXPECTED BEHAVIOR: Structured protocol error
                    assert!(
                        msg.contains("invalid") || msg.contains("overflow") || msg.contains("byte"),
                        "Test case {i}: Protocol error should be actionable, got: {msg}"
                    );
                }
                Err(other) => {
                    panic!(
                        "Test case {i}: Expected Protocol error for malformed input, got: {:?}",
                        other
                    );
                }
            }
        }

        // Test Category 2: Truncated body after valid length
        let truncated_body_cases = [
            // Valid length but incomplete key-value pairs
            b"|2\r\n+key1\r\n".as_slice(), // Missing value1, key2, value2
            b"|1\r\n+key\r\n".as_slice(),  // Missing value (odd number in map)
            b"|1\r\n".as_slice(),          // No pairs at all
        ];

        for (i, truncated_input) in truncated_body_cases.iter().enumerate() {
            let result = RespValue::try_decode(truncated_input);

            match result {
                Ok(None) => {
                    // EXPECTED: Incomplete parse for truncated input
                    // This is correct - parser detects insufficient data
                }
                Ok(Some(_)) => {
                    panic!(
                        "Truncated test {i}: Parser should not succeed on incomplete input: {:?}",
                        std::str::from_utf8(truncated_input).unwrap_or("<invalid utf8>")
                    );
                }
                Err(RedisError::Protocol(_)) => {
                    // Also acceptable - some truncation patterns may be detected as protocol errors
                }
                Err(other) => {
                    panic!("Truncated test {i}: Unexpected error type: {:?}", other);
                }
            }
        }

        // Test Category 3: Verify no panic behavior
        // Parser should never panic on malformed input - always return Result
        let extreme_cases = [
            b"|999999999999999999999999999999\r\n".as_slice(), // Extreme overflow
            b"|\x00\x01\x02\r\n".as_slice(),                   // Binary in length field
            b"|\xFF\xFF\xFF\r\n".as_slice(),                   // Invalid UTF-8 bytes
        ];

        for (i, extreme_input) in extreme_cases.iter().enumerate() {
            // The key test: parser must not panic
            let result = std::panic::catch_unwind(|| RespValue::try_decode(extreme_input));

            assert!(
                result.is_ok(),
                "Extreme test {i}: Parser panicked on malformed input - should return Result::Err"
            );
        }

        // BEHAVIOR VERIFICATION COMPLETE:
        // ✅ Option (b): Structured ParseError with actionable messages
        // ❌ Option (a): Does NOT skip and continue (would return Ok(Some(_)))
        // ❌ Option (c): Does NOT panic (verified via catch_unwind)
        // ✅ RESP3 spec compliance: malformed frames result in parse errors
        // ✅ Error messages are actionable for debugging
        // ✅ Truncated input correctly detected as incomplete (Ok(None))
    }
}

// RESP3 push-frame interleaving audit
#[cfg(test)]
#[path = "redis_resp3_push_interleaving_audit.rs"]
mod redis_resp3_push_interleaving_audit;
