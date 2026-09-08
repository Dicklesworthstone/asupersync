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

/// Decode a reply that is either a bulk string or "no value".
///
/// The client negotiates RESP3 (`HELLO 3`), and Redis 7 answers a missing
/// hash field or key with the RESP3 null (`_\r\n`), not the RESP2 null bulk
/// (`$-1\r\n`). Accepting only `BulkString(None)` turned every miss into a
/// protocol error against a real server (found by the real-server suite).
fn optional_bulk_reply(resp: RespValue, command: &str) -> Result<Option<Vec<u8>>, RedisError> {
    match resp {
        RespValue::BulkString(Some(bytes)) => Ok(Some(bytes)),
        RespValue::BulkString(None) | RespValue::Null => Ok(None),
        other => Err(RedisError::Protocol(format!(
            "{command} expected bulk string, got {other:?}"
        ))),
    }
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
    pub fn try_decode_with_limits(
        buf: &[u8],
        limits: &RedisProtocolLimits,
    ) -> Result<Option<(Self, usize)>, RedisError> {
        Self::try_decode_with_limits_and_attribute_policy(buf, limits, false)
    }

    fn try_decode_response_with_limits(
        buf: &[u8],
        limits: &RedisProtocolLimits,
    ) -> Result<Option<(Self, usize)>, RedisError> {
        Self::try_decode_with_limits_and_attribute_policy(buf, limits, true)
    }

    #[allow(clippy::too_many_lines)]
    #[allow(clippy::use_self)]
    fn try_decode_with_limits_and_attribute_policy(
        buf: &[u8],
        limits: &RedisProtocolLimits,
        skip_nested_attributes: bool,
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

        fn check_value_complete(
            buf: &[u8],
            mut i: usize,
            depth: usize,
            limits: &RedisProtocolLimits,
            skip_nested_attributes: bool,
        ) -> Result<Option<usize>, RedisError> {
            if !skip_nested_attributes {
                return check_complete(buf, i, depth, limits, false);
            }

            loop {
                let Some(next) = check_complete(buf, i, depth, limits, true)? else {
                    return Ok(None);
                };
                if buf.get(i) != Some(&b'|') {
                    return Ok(Some(next));
                }

                // RESP3 attributes are metadata prefixes, not values in the
                // enclosing aggregate. Skip any number of complete attribute
                // frames and require the actual value that follows them.
                i = next;
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
            skip_nested_attributes: bool,
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
                            match check_value_complete(
                                buf,
                                i,
                                depth + 1,
                                limits,
                                skip_nested_attributes,
                            )? {
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
                        match check_value_complete(
                            buf,
                            i,
                            depth + 1,
                            limits,
                            skip_nested_attributes,
                        )? {
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
        if check_complete(buf, 0, 0, limits, skip_nested_attributes)?.is_none() {
            return Ok(None);
        }

        fn decode_value_at(
            buf: &[u8],
            mut i: usize,
            depth: usize,
            limits: &RedisProtocolLimits,
            skip_nested_attributes: bool,
        ) -> Result<Decoded, RedisError> {
            if !skip_nested_attributes {
                return decode_at(buf, i, depth, limits, false);
            }

            loop {
                match decode_at(buf, i, depth, limits, true)? {
                    Decoded::NeedMore => return Ok(Decoded::NeedMore),
                    Decoded::Ok {
                        value: RespValue::Attribute(_),
                        next,
                    } => i = next,
                    decoded @ Decoded::Ok { .. } => return Ok(decoded),
                }
            }
        }

        #[allow(clippy::too_many_lines)]
        fn decode_at(
            buf: &[u8],
            i: usize,
            depth: usize,
            limits: &RedisProtocolLimits,
            skip_nested_attributes: bool,
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
                            match decode_value_at(
                                buf,
                                pos,
                                depth + 1,
                                limits,
                                skip_nested_attributes,
                            )? {
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
                        match decode_value_at(buf, pos, depth + 1, limits, skip_nested_attributes)?
                        {
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
                            let key = match decode_value_at(
                                buf,
                                pos,
                                depth + 1,
                                limits,
                                skip_nested_attributes,
                            )? {
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
                            let val = match decode_value_at(
                                buf,
                                pos,
                                depth + 1,
                                limits,
                                skip_nested_attributes,
                            )? {
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
                        let key = match decode_value_at(
                            buf,
                            pos,
                            depth + 1,
                            limits,
                            skip_nested_attributes,
                        )? {
                            Decoded::NeedMore => return Ok(Decoded::NeedMore),
                            Decoded::Ok { value, next } => {
                                pos = next;
                                value
                            }
                        };
                        let val = match decode_value_at(
                            buf,
                            pos,
                            depth + 1,
                            limits,
                            skip_nested_attributes,
                        )? {
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

        match decode_at(buf, 0, 0, limits, skip_nested_attributes)? {
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

fn classify_command_response(response: RespValue) -> Result<RespValue, RedisError> {
    match response {
        RespValue::Error(message) => Err(RedisError::Redis(message)),
        RespValue::BlobError(message) => Err(RedisError::Redis(
            String::from_utf8_lossy(&message).into_owned(),
        )),
        other => Ok(other),
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
/// | `max_bulk_string_len` | 512 MiB | Protocol bulk-length ceiling; `RedisConnection` also bounds buffered replies by `max_frame_size` |
#[derive(Debug, Clone, Copy)]
pub struct RedisProtocolLimits {
    /// Maximum RESP frame size in bytes.
    pub max_frame_size: usize,
    /// Maximum RESP array nesting depth.
    pub max_nesting_depth: usize,
    /// Maximum RESP array element count.
    pub max_array_len: usize,
    /// Maximum declared bulk string length.
    ///
    /// When decoding from a `RedisConnection`, the effective buffered-reply
    /// limit is the smaller of this value and [`Self::max_frame_size`] (minus
    /// RESP framing bytes). Standalone [`RespValue::try_decode_with_limits`]
    /// calls apply this declared-length limit but do not buffer network input.
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

#[derive(Debug, Clone, Copy)]
enum RespScanContainerKind {
    Fixed {
        remaining: usize,
    },
    Streamed {
        is_map: bool,
        children: usize,
        max_children: usize,
    },
}

#[derive(Debug, Clone, Copy)]
struct RespScanContainer {
    kind: RespScanContainerKind,
    counts_as_parent_value: bool,
}

#[derive(Debug, Clone, Copy)]
enum RespScanPending {
    Type,
    Line {
        tag: u8,
        start: usize,
        search_from: usize,
    },
    FixedPayload {
        end_data: usize,
        end_crlf: usize,
    },
    StreamedBlobChunkLine {
        total_len: usize,
        start: usize,
        search_from: usize,
    },
    StreamedBlobChunkPayload {
        total_len: usize,
        end_data: usize,
        end_crlf: usize,
    },
}

#[derive(Debug)]
struct RespFrameScanner {
    cursor: usize,
    stack: Vec<RespScanContainer>,
    pending: RespScanPending,
    complete_len: Option<usize>,
    #[cfg(test)]
    work_units: usize,
}

impl RespFrameScanner {
    fn new() -> Self {
        Self {
            cursor: 0,
            stack: Vec::new(),
            pending: RespScanPending::Type,
            complete_len: None,
            #[cfg(test)]
            work_units: 0,
        }
    }

    fn reset(&mut self) {
        *self = Self::new();
    }

    fn find_crlf_incremental(&mut self, buf: &[u8], mut i: usize) -> Option<usize> {
        while i + 1 < buf.len() {
            #[cfg(test)]
            {
                self.work_units = self.work_units.saturating_add(1);
            }
            if buf[i] == b'\r' && buf[i + 1] == b'\n' {
                return Some(i);
            }
            i += 1;
        }
        None
    }

    fn finish_container(&mut self, counts_as_parent_value: bool) -> Result<(), RedisError> {
        if counts_as_parent_value {
            self.finish_value()
        } else {
            Ok(())
        }
    }

    fn finish_value(&mut self) -> Result<(), RedisError> {
        loop {
            let Some(container) = self.stack.last_mut() else {
                self.complete_len = Some(self.cursor);
                return Ok(());
            };

            match &mut container.kind {
                RespScanContainerKind::Fixed { remaining } => {
                    *remaining = remaining.checked_sub(1).ok_or_else(|| {
                        RedisError::Protocol(
                            "incremental RESP scanner exhausted aggregate children".to_string(),
                        )
                    })?;
                    if *remaining != 0 {
                        return Ok(());
                    }
                }
                RespScanContainerKind::Streamed {
                    children,
                    max_children,
                    ..
                } => {
                    *children = children.checked_add(1).ok_or_else(|| {
                        RedisError::Protocol("streamed aggregate length overflow".to_string())
                    })?;
                    if *children > *max_children {
                        return Err(RedisError::Protocol(
                            "streamed aggregate length exceeds configured maximum".to_string(),
                        ));
                    }
                    return Ok(());
                }
            }

            let Some(completed) = self.stack.pop() else {
                return Err(RedisError::Protocol(
                    "incremental RESP scanner lost aggregate frame".to_string(),
                ));
            };
            if !completed.counts_as_parent_value {
                return Ok(());
            }
        }
    }

    fn open_fixed_container(
        &mut self,
        remaining: usize,
        counts_as_parent_value: bool,
    ) -> Result<(), RedisError> {
        if remaining == 0 {
            return self.finish_container(counts_as_parent_value);
        }
        self.stack.push(RespScanContainer {
            kind: RespScanContainerKind::Fixed { remaining },
            counts_as_parent_value,
        });
        Ok(())
    }

    fn close_streamed_container(&mut self) -> Result<(), RedisError> {
        let Some(container) = self.stack.pop() else {
            return Err(RedisError::Protocol(
                "RESP3 streamed terminator without aggregate".to_string(),
            ));
        };
        let RespScanContainerKind::Streamed {
            is_map, children, ..
        } = container.kind
        else {
            return Err(RedisError::Protocol(
                "RESP3 streamed terminator inside fixed aggregate".to_string(),
            ));
        };
        if is_map && children % 2 != 0 {
            return Err(RedisError::Protocol(
                "RESP3 streamed map ended after an odd number of values".to_string(),
            ));
        }
        self.finish_container(container.counts_as_parent_value)
    }

    #[allow(clippy::too_many_lines)]
    fn scan(
        &mut self,
        buf: &[u8],
        limits: &RedisProtocolLimits,
    ) -> Result<Option<usize>, RedisError> {
        loop {
            if let Some(complete_len) = self.complete_len {
                return Ok(Some(complete_len));
            }

            match self.pending {
                RespScanPending::Type => {
                    if self.cursor >= buf.len() {
                        return Ok(None);
                    }
                    if self.stack.len() > limits.max_nesting_depth {
                        return Err(RedisError::Protocol(format!(
                            "RESP nesting depth exceeds maximum ({})",
                            limits.max_nesting_depth
                        )));
                    }

                    if let Some(RespScanContainer {
                        kind:
                            RespScanContainerKind::Streamed {
                                is_map: _,
                                children,
                                max_children,
                            },
                        ..
                    }) = self.stack.last()
                    {
                        if buf[self.cursor] == b'.' {
                            if buf.len() < self.cursor + 3 {
                                return Ok(None);
                            }
                            #[cfg(test)]
                            {
                                self.work_units = self.work_units.saturating_add(3);
                            }
                            if &buf[self.cursor..self.cursor + 3] != b".\r\n" {
                                return Err(RedisError::Protocol(
                                    "invalid RESP3 streamed aggregate terminator".to_string(),
                                ));
                            }
                            self.cursor += 3;
                            self.close_streamed_container()?;
                            continue;
                        }
                        if children >= max_children {
                            return Err(RedisError::Protocol(format!(
                                "streamed aggregate length exceeds maximum {}",
                                limits.max_array_len
                            )));
                        }
                    }

                    let tag = buf[self.cursor];
                    #[cfg(test)]
                    {
                        self.work_units = self.work_units.saturating_add(1);
                    }
                    if !matches!(
                        tag,
                        b'+' | b'-'
                            | b':'
                            | b','
                            | b'('
                            | b'_'
                            | b'#'
                            | b'$'
                            | b'='
                            | b'!'
                            | b'*'
                            | b'~'
                            | b'>'
                            | b'%'
                            | b'|'
                    ) {
                        return Err(RedisError::Protocol(format!(
                            "unknown RESP type byte: 0x{tag:02x}"
                        )));
                    }
                    self.pending = RespScanPending::Line {
                        tag,
                        start: self.cursor,
                        search_from: self.cursor + 1,
                    };
                }
                RespScanPending::Line {
                    tag,
                    start,
                    search_from,
                } => {
                    let Some(end) = self.find_crlf_incremental(buf, search_from) else {
                        self.pending = RespScanPending::Line {
                            tag,
                            start,
                            search_from: buf.len().saturating_sub(1).max(start + 1),
                        };
                        return Ok(None);
                    };
                    let payload = &buf[start + 1..end];
                    self.cursor = end + 2;
                    self.pending = RespScanPending::Type;

                    match tag {
                        b'+' | b'-' | b':' | b',' | b'(' | b'_' | b'#' => {
                            self.finish_value()?;
                        }
                        b'$' | b'=' | b'!' => {
                            if tag == b'$' && payload == b"?" {
                                self.pending = RespScanPending::StreamedBlobChunkLine {
                                    total_len: 0,
                                    start: self.cursor,
                                    search_from: self.cursor + 1,
                                };
                                continue;
                            }
                            let len = parse_i64_ascii(payload)?;
                            if len == -1 && tag == b'$' {
                                self.finish_value()?;
                                continue;
                            }
                            if len < 0 {
                                return Err(RedisError::Protocol(format!(
                                    "invalid {} length for byte 0x{tag:02x}: {len}",
                                    match tag {
                                        b'$' => "bulk string",
                                        b'=' => "verbatim string",
                                        b'!' => "blob error",
                                        _ => "bulk-shape",
                                    }
                                )));
                            }
                            let len = usize::try_from(len).map_err(|_| {
                                RedisError::Protocol(format!("invalid bulk-shape length: {len}"))
                            })?;
                            if len > limits.max_bulk_string_len {
                                return Err(RedisError::Protocol(format!(
                                    "bulk-shape length {len} exceeds maximum {}",
                                    limits.max_bulk_string_len
                                )));
                            }
                            let end_data = self.cursor.saturating_add(len);
                            self.pending = RespScanPending::FixedPayload {
                                end_data,
                                end_crlf: end_data.saturating_add(2),
                            };
                        }
                        b'*' | b'~' | b'>' | b'%' | b'|' => {
                            if payload == b"?" {
                                if !matches!(tag, b'*' | b'~' | b'%') {
                                    return Err(RedisError::Protocol(format!(
                                        "RESP3 streamed aggregate not supported for type byte 0x{tag:02x}"
                                    )));
                                }
                                let counts_as_parent_value = tag != b'|' || self.stack.is_empty();
                                self.stack.push(RespScanContainer {
                                    kind: RespScanContainerKind::Streamed {
                                        is_map: tag == b'%',
                                        children: 0,
                                        max_children: if tag == b'%' {
                                            limits.max_array_len.saturating_mul(2)
                                        } else {
                                            limits.max_array_len
                                        },
                                    },
                                    counts_as_parent_value,
                                });
                                continue;
                            }
                            let n = parse_i64_ascii(payload)?;
                            if n == -1 && tag == b'*' {
                                self.finish_value()?;
                                continue;
                            }
                            if n < 0 {
                                return Err(RedisError::Protocol(format!(
                                    "invalid aggregate length: {n}"
                                )));
                            }
                            let n = usize::try_from(n).map_err(|_| {
                                RedisError::Protocol(format!("invalid aggregate length: {n}"))
                            })?;
                            if n > limits.max_array_len {
                                return Err(RedisError::Protocol(format!(
                                    "aggregate length {n} exceeds maximum {}",
                                    limits.max_array_len
                                )));
                            }
                            let children = if matches!(tag, b'%' | b'|') {
                                n.checked_mul(2).ok_or_else(|| {
                                    RedisError::Protocol("aggregate length overflow".to_string())
                                })?
                            } else {
                                n
                            };
                            let counts_as_parent_value = tag != b'|' || self.stack.is_empty();
                            self.open_fixed_container(children, counts_as_parent_value)?;
                        }
                        _ => unreachable!(),
                    }
                }
                RespScanPending::FixedPayload { end_data, end_crlf } => {
                    #[cfg(test)]
                    {
                        self.work_units = self.work_units.saturating_add(1);
                    }
                    if buf.len() < end_crlf {
                        return Ok(None);
                    }
                    if buf.get(end_data) != Some(&b'\r') || buf.get(end_data + 1) != Some(&b'\n') {
                        return Err(RedisError::Protocol(
                            "bulk-shape payload missing trailing CRLF".to_string(),
                        ));
                    }
                    self.cursor = end_crlf;
                    self.pending = RespScanPending::Type;
                    self.finish_value()?;
                }
                RespScanPending::StreamedBlobChunkLine {
                    total_len,
                    start,
                    search_from,
                } => {
                    if start >= buf.len() {
                        return Ok(None);
                    }
                    if buf[start] != b';' {
                        return Err(RedisError::Protocol(format!(
                            "RESP3 streamed blob chunk must start with ';', got 0x{:02x}",
                            buf[start]
                        )));
                    }
                    let Some(end) = self.find_crlf_incremental(buf, search_from) else {
                        self.pending = RespScanPending::StreamedBlobChunkLine {
                            total_len,
                            start,
                            search_from: buf.len().saturating_sub(1).max(start + 1),
                        };
                        return Ok(None);
                    };
                    let len = parse_i64_ascii(&buf[start + 1..end])?;
                    if len < 0 {
                        return Err(RedisError::Protocol(format!(
                            "invalid streamed blob chunk length: {len}"
                        )));
                    }
                    let len = usize::try_from(len).map_err(|_| {
                        RedisError::Protocol(format!("invalid streamed blob chunk length: {len}"))
                    })?;
                    self.cursor = end + 2;
                    if len == 0 {
                        self.pending = RespScanPending::Type;
                        self.finish_value()?;
                        continue;
                    }
                    let total_len = total_len.checked_add(len).ok_or_else(|| {
                        RedisError::Protocol("streamed blob length overflow".to_string())
                    })?;
                    if total_len > limits.max_bulk_string_len {
                        return Err(RedisError::Protocol(format!(
                            "streamed blob length {total_len} exceeds maximum {}",
                            limits.max_bulk_string_len
                        )));
                    }
                    let end_data = self.cursor.saturating_add(len);
                    self.pending = RespScanPending::StreamedBlobChunkPayload {
                        total_len,
                        end_data,
                        end_crlf: end_data.saturating_add(2),
                    };
                }
                RespScanPending::StreamedBlobChunkPayload {
                    total_len,
                    end_data,
                    end_crlf,
                } => {
                    #[cfg(test)]
                    {
                        self.work_units = self.work_units.saturating_add(1);
                    }
                    if buf.len() < end_crlf {
                        return Ok(None);
                    }
                    if buf.get(end_data) != Some(&b'\r') || buf.get(end_data + 1) != Some(&b'\n') {
                        return Err(RedisError::Protocol(
                            "streamed blob chunk missing trailing CRLF".to_string(),
                        ));
                    }
                    self.cursor = end_crlf;
                    self.pending = RespScanPending::StreamedBlobChunkLine {
                        total_len,
                        start: self.cursor,
                        search_from: self.cursor + 1,
                    };
                }
            }
        }
    }

    #[cfg(test)]
    fn work_units(&self) -> usize {
        self.work_units
    }
}

#[derive(Debug)]
struct RespReadBuffer {
    buf: Vec<u8>,
    pos: usize,
    frame_scanner: RespFrameScanner,
}

impl RespReadBuffer {
    fn new() -> Self {
        Self {
            buf: Vec::new(),
            pos: 0,
            frame_scanner: RespFrameScanner::new(),
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

    fn response_frame_len(
        &mut self,
        limits: &RedisProtocolLimits,
    ) -> Result<Option<usize>, RedisError> {
        let available = &self.buf[self.pos..];
        self.frame_scanner.scan(available, limits)
    }

    fn consume(&mut self, n: usize) {
        self.pos = self.pos.saturating_add(n);
        self.frame_scanner.reset();
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
        self.write_command(cx, &hello_args).await?;
        match self.read_response(cx).await? {
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

            let protocol_limits = self.config.protocol_limits;
            let frame_limit = protocol_limits.max_frame_size;
            if let Some(frame_len) = self.read_buf.response_frame_len(&protocol_limits)? {
                if frame_len > frame_limit {
                    return Err(RedisError::Protocol(format!(
                        "RESP frame exceeds limit ({frame_limit} bytes)"
                    )));
                }
                let Some((value, consumed)) = RespValue::try_decode_response_with_limits(
                    self.read_buf.available(),
                    &protocol_limits,
                )?
                else {
                    return Err(RedisError::Protocol(
                        "incremental RESP scanner completed before authoritative decoder"
                            .to_string(),
                    ));
                };
                if consumed != frame_len {
                    return Err(RedisError::Protocol(format!(
                        "incremental RESP scanner boundary {frame_len} disagrees with decoded boundary {consumed}"
                    )));
                }
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
        classify_command_response(self.read_response(cx).await?)
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
        optional_bulk_reply(resp, "HGET")
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
///   * The inner `Result` is per-command: a RESP2 `-ERR ...` or RESP3
///     blob-error reply becomes `Err(RedisError::Redis(msg))`; every non-error
///     reply (including nil) becomes `Ok(value)`. The connection stays healthy
///     and is returned to the pool. (br-asupersync-pr32li)
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
    /// corresponds positionally to a queued command. A RESP2 `-ERR` or RESP3
    /// blob-error reply becomes `Err(RedisError::Redis(msg))` for that single
    /// command; the loop continues to drain remaining responses so the
    /// wire-protocol framing stays in sync. The connection is returned to the
    /// pool regardless of how many per-command errors occurred.
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
        // connection. Application-level RESP2 and RESP3 error replies become
        // per-command `Err`s in the inner Result so a failed command in a
        // pipeline doesn't tear down the whole batch or the connection.
        let mut out = Vec::with_capacity(self.encoded.len());
        for _ in 0..self.encoded.len() {
            let resp = conn.read_response(cx).await?;
            out.push(classify_command_response(resp));
        }

        // Protocol exchange complete — defuse the guard so the connection
        // returns to the pool instead of being discarded. Server error replies
        // are application-level and do NOT invalidate the connection.
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
    /// the function and only reset it to `false` on successful and
    /// server-error reply paths — so on a transient network failure mid-write
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

        match classify_command_response(resp) {
            Ok(RespValue::SimpleString(s)) if s == "QUEUED" => {
                self.conn = Some(conn.defuse());
                self.queued_commands = self.queued_commands.saturating_add(1);
                Ok(())
            }
            Err(error) => {
                self.conn = Some(conn.defuse());
                Err(error)
            }
            Ok(other) => {
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

        // `exec_no_init` classifies both RESP2 and RESP3 top-level server
        // errors before this transaction-result shape match.
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

#[derive(Clone, Copy)]
enum PubSubControlAction {
    SubscribeChannel,
    SubscribePattern,
    UnsubscribeChannel,
    UnsubscribePattern,
}

impl PubSubControlAction {
    const fn command(self) -> &'static str {
        match self {
            Self::SubscribeChannel => "SUBSCRIBE",
            Self::SubscribePattern => "PSUBSCRIBE",
            Self::UnsubscribeChannel => "UNSUBSCRIBE",
            Self::UnsubscribePattern => "PUNSUBSCRIBE",
        }
    }

    const fn expected_kind(self) -> PubSubSubscriptionKind {
        match self {
            Self::SubscribeChannel => PubSubSubscriptionKind::Subscribe,
            Self::SubscribePattern => PubSubSubscriptionKind::PatternSubscribe,
            Self::UnsubscribeChannel => PubSubSubscriptionKind::Unsubscribe,
            Self::UnsubscribePattern => PubSubSubscriptionKind::PatternUnsubscribe,
        }
    }
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

    async fn read_ping_event(
        &mut self,
        cx: &Cx,
        expected_payload: Option<&[u8]>,
    ) -> Result<PubSubEvent, RedisError> {
        self.pubsub.read_ping_event(cx, expected_payload).await
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

    fn validate_subscription_remaining(
        &self,
        command: &str,
        reported: i64,
    ) -> Result<(), RedisError> {
        let reported = usize::try_from(reported).map_err(|_| {
            RedisError::Protocol(format!(
                "{command} acknowledgement reported a negative or out-of-range remaining subscription count"
            ))
        })?;
        let expected = self
            .pubsub
            .channels
            .len()
            .checked_add(self.pubsub.patterns.len())
            .ok_or_else(|| {
                RedisError::Protocol(format!("{command} tracked subscription count overflowed"))
            })?;
        if reported != expected {
            return Err(RedisError::Protocol(format!(
                "{command} acknowledgement reported {reported} remaining subscriptions; tracked state requires {expected}"
            )));
        }
        Ok(())
    }

    fn handle_control_event(
        &mut self,
        action: PubSubControlAction,
        expected_targets: &mut Vec<String>,
        event: PubSubEvent,
    ) -> Result<(), RedisError> {
        let command = action.command();
        match event {
            message @ PubSubEvent::Message(_) => {
                self.push_pending_event(message);
                Ok(())
            }
            PubSubEvent::Pong(_) => Err(RedisError::Protocol(format!(
                "{command} received an unsolicited PONG control reply"
            ))),
            PubSubEvent::Subscription {
                kind,
                channel,
                remaining,
            } => {
                let expected_kind = action.expected_kind();
                if kind != expected_kind {
                    return Err(RedisError::Protocol(format!(
                        "{command} received unexpected {kind:?} acknowledgement; expected {expected_kind:?}"
                    )));
                }
                RedisPubSub::acknowledge_subscription_target(expected_targets, &channel, command)?;
                match action {
                    PubSubControlAction::SubscribeChannel => self.track_channel(&channel),
                    PubSubControlAction::SubscribePattern => self.track_pattern(&channel),
                    PubSubControlAction::UnsubscribeChannel => self.untrack_channel(&channel),
                    PubSubControlAction::UnsubscribePattern => self.untrack_pattern(&channel),
                }
                self.validate_subscription_remaining(command, remaining)
            }
        }
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

impl Drop for RedisPubSub {
    fn drop(&mut self) {
        if !self.channels.is_empty() || !self.patterns.is_empty() || self.poisoned {
            let _ = self.conn.stream.shutdown_transport();
        }
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
        if remaining < 0 {
            return Err(RedisError::Protocol(
                "pubsub subscription remaining-count must be nonnegative".to_string(),
            ));
        }
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
            _ => {
                return Err(RedisError::Protocol(
                    "pubsub expected an array or push event".to_string(),
                ));
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

    fn parse_ping_event(
        value: RespValue,
        expected_payload: Option<&[u8]>,
    ) -> Result<PubSubEvent, RedisError> {
        match value {
            RespValue::SimpleString(pong) if pong == "PONG" => {
                if expected_payload.is_none() {
                    Ok(PubSubEvent::Pong(None))
                } else {
                    Err(RedisError::Protocol(
                        "pubsub PING response did not echo the requested payload".to_string(),
                    ))
                }
            }
            RespValue::BulkString(Some(actual)) => match expected_payload {
                Some(expected) if actual == expected => Ok(PubSubEvent::Pong(Some(actual))),
                _ => Err(RedisError::Protocol(
                    "pubsub PING response payload did not match the request".to_string(),
                )),
            },
            RespValue::Array(Some(items)) => {
                if let [
                    RespValue::BulkString(Some(kind)),
                    RespValue::BulkString(Some(actual)),
                ] = items.as_slice()
                    && kind == b"pong"
                {
                    let matches_request = match expected_payload {
                        None => actual.is_empty(),
                        Some(expected) => actual == expected,
                    };
                    if matches_request {
                        return Ok(PubSubEvent::Pong(Some(actual.clone())));
                    }
                    return Err(RedisError::Protocol(
                        "pubsub PING response payload did not match the request".to_string(),
                    ));
                }

                let event = Self::parse_event(RespValue::Array(Some(items))).map_err(|_| {
                    RedisError::Protocol(
                        "pubsub PING received a malformed aggregate response".to_string(),
                    )
                })?;
                match event {
                    PubSubEvent::Message(_) => Ok(event),
                    PubSubEvent::Pong(_) => Err(RedisError::Protocol(
                        "pubsub PING received a non-canonical aggregate response".to_string(),
                    )),
                    PubSubEvent::Subscription { .. } => Err(RedisError::Protocol(
                        "pubsub PING received unexpected subscription control traffic".to_string(),
                    )),
                }
            }
            value @ RespValue::Push(_) => {
                let event = Self::parse_event(value).map_err(|_| {
                    RedisError::Protocol("pubsub PING received a malformed push event".to_string())
                })?;
                match event {
                    PubSubEvent::Message(_) => Ok(event),
                    PubSubEvent::Pong(_) | PubSubEvent::Subscription { .. } => {
                        Err(RedisError::Protocol(
                            "pubsub PING received unexpected control push traffic".to_string(),
                        ))
                    }
                }
            }
            _ => Err(RedisError::Protocol(
                "pubsub PING expected a PONG reply or interleaved event".to_string(),
            )),
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

    async fn read_ping_event(
        &mut self,
        cx: &Cx,
        expected_payload: Option<&[u8]>,
    ) -> Result<PubSubEvent, RedisError> {
        let response = self.conn.read_pubsub_response(cx).await?;
        Self::parse_ping_event(response, expected_payload)
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
            guard.handle_control_event(
                PubSubControlAction::SubscribeChannel,
                &mut expected_acks,
                event,
            )?;
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
            guard.handle_control_event(
                PubSubControlAction::SubscribePattern,
                &mut expected_acks,
                event,
            )?;
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
            guard.handle_control_event(
                PubSubControlAction::UnsubscribeChannel,
                &mut expected_acks,
                event,
            )?;
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
            guard.handle_control_event(
                PubSubControlAction::UnsubscribePattern,
                &mut expected_acks,
                event,
            )?;
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
            match guard.read_ping_event(cx, payload).await? {
                PubSubEvent::Pong(_) => {
                    guard.commit();
                    return Ok(());
                }
                event @ PubSubEvent::Message(_) => {
                    guard.push_pending_event(event);
                    // Beyond the cap, interleaved messages are dropped to
                    // bound memory.  This is a defensive limit — in normal
                    // operation PONG arrives within a few round-trips.
                }
                PubSubEvent::Subscription { .. } => {
                    return Err(RedisError::Protocol(
                        "pubsub PING received unexpected subscription control traffic".to_string(),
                    ));
                }
            }
        }
    }

    /// Reconnect and restore tracked subscriptions.
    pub async fn reconnect(&mut self, cx: &Cx) -> Result<(), RedisError> {
        let channels = self.channels.clone();
        let patterns = self.patterns.clone();
        let pubsub_dropped_events = self.pubsub_dropped_events;
        let pubsub_lag_reported = self.pubsub_lag_reported;

        // Replay subscriptions against empty state on a temporary connection.
        // Redis acknowledgement counts describe the new connection, not the
        // stale connection being replaced. Keeping `self` untouched until the
        // full replay succeeds also preserves the desired subscription set for
        // a later retry when any acknowledgement fails validation.
        let mut replacement = Self::connect(cx, self.config.clone()).await?;
        replacement.pubsub_dropped_events = pubsub_dropped_events;
        replacement.pubsub_lag_reported = pubsub_lag_reported;

        if !channels.is_empty() {
            let channel_refs: Vec<&str> = channels.iter().map(String::as_str).collect();
            replacement.subscribe(cx, &channel_refs).await?;
        }
        if !patterns.is_empty() {
            let pattern_refs: Vec<&str> = patterns.iter().map(String::as_str).collect();
            replacement.psubscribe(cx, &pattern_refs).await?;
        }
        *self = replacement;
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

#[cfg(any(test, feature = "test-internals"))]
#[allow(dead_code)]
/// Test-internals hook exposing request-contextual Pub/Sub PING parsing.
///
/// Intended for structure-aware fuzz targets that validate exact binary echo
/// handling without widening the production API.
pub fn parse_pubsub_ping_event_for_fuzz(
    value: RespValue,
    expected_payload: Option<&[u8]>,
) -> Result<PubSubEvent, RedisError> {
    RedisPubSub::parse_ping_event(value, expected_payload)
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
include!("redis_tests.rs");

// RESP3 push-frame interleaving audit
#[cfg(test)]
#[path = "redis_resp3_push_interleaving_audit.rs"]
mod redis_resp3_push_interleaving_audit;
