//! Redis client with RESP protocol and Cx integration.
//!
//! This module provides a pure Rust Redis client implementing the RESP
//! (REdis Serialization Protocol) with Cx integration for cancel-correct
//! command execution.

use crate::cx::Cx;
use crate::io::{AsyncRead, AsyncWriteExt, ReadBuf};
use crate::net::TcpStream;
use crate::sync::{GenericPool, Pool as _, PoolConfig, PoolError, PooledResource};
use std::collections::VecDeque;
use std::fmt;
use std::future::Future;
use std::io;
use std::pin::Pin;
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
        matches!(self, Self::PoolExhausted)
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
            "expected integer, got empty".to_string(),
        ));
    }

    let mut i = 0;
    let mut neg = false;
    if bytes[0] == b'-' {
        neg = true;
        i = 1;
        if i == bytes.len() {
            return Err(RedisError::Protocol(
                "expected integer after '-'".to_string(),
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
        acc = acc * 10 + digit;
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

/// RESP (REdis Serialization Protocol) value.
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
        }
    }

    /// Decode one RESP value from the provided buffer.
    ///
    /// Returns `Ok(None)` if more bytes are required.
    #[allow(clippy::too_many_lines)]
    #[allow(clippy::use_self)]
    fn try_decode(buf: &[u8]) -> Result<Option<(Self, usize)>, RedisError> {
        /// Maximum nesting depth for RESP arrays to prevent stack overflow
        /// from malicious deeply-nested responses.
        const MAX_NESTING_DEPTH: usize = 64;

        enum Decoded {
            NeedMore,
            Ok { value: RespValue, next: usize },
        }

        #[allow(clippy::too_many_lines)]
        fn decode_at(buf: &[u8], i: usize, depth: usize) -> Result<Decoded, RedisError> {
            if depth > MAX_NESTING_DEPTH {
                return Err(RedisError::Protocol(format!(
                    "RESP nesting depth exceeds maximum ({MAX_NESTING_DEPTH})"
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
                b'*' => {
                    const MAX_ARRAY_LEN: usize = 1_000_000;
                    let Some(end) = find_crlf(buf, i + 1) else {
                        return Ok(Decoded::NeedMore);
                    };
                    let n = parse_i64_ascii(&buf[i + 1..end])?;
                    if n == -1 {
                        return Ok(Decoded::Ok {
                            value: RespValue::Array(None),
                            next: end + 2,
                        });
                    }
                    if n < -1 {
                        return Err(RedisError::Protocol(format!("invalid array length: {n}")));
                    }
                    let n = usize::try_from(n)
                        .map_err(|_| RedisError::Protocol(format!("invalid array length: {n}")))?;
                    // Guard against absurdly large declared arrays (limit to 1M elements)
                    if n > MAX_ARRAY_LEN {
                        return Err(RedisError::Protocol(format!(
                            "array length {n} exceeds maximum {MAX_ARRAY_LEN}"
                        )));
                    }
                    let mut items = Vec::with_capacity(n);
                    let mut pos = end + 2;
                    for _ in 0..n {
                        match decode_at(buf, pos, depth + 1)? {
                            Decoded::NeedMore => return Ok(Decoded::NeedMore),
                            Decoded::Ok { value, next } => {
                                items.push(value);
                                pos = next;
                            }
                        }
                    }
                    Ok(Decoded::Ok {
                        value: RespValue::Array(Some(items)),
                        next: pos,
                    })
                }
                other => Err(RedisError::Protocol(format!(
                    "unknown RESP type byte: 0x{other:02x}"
                ))),
            }
        }

        match decode_at(buf, 0, 0)? {
            Decoded::NeedMore => Ok(None),
            Decoded::Ok { value, next } => Ok(Some((value, next))),
        }
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

fn expect_ok_response(resp: &RespValue, command: &str) -> Result<(), RedisError> {
    if resp.is_ok() {
        Ok(())
    } else {
        Err(RedisError::Protocol(format!(
            "{command} expected +OK, got {resp:?}"
        )))
    }
}

const MAX_RESP_FRAME_SIZE: usize = 16 * 1024 * 1024;

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
}

impl std::fmt::Debug for RedisConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RedisConfig")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("database", &self.database)
            .field("username", &self.username)
            .field("password", &self.password.as_ref().map(|_| "[REDACTED]"))
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
        }
    }
}

impl RedisConfig {
    /// Create config from a Redis URL.
    pub fn from_url(url: &str) -> Result<Self, RedisError> {
        let url = url
            .strip_prefix("redis://")
            .ok_or_else(|| RedisError::InvalidUrl(url.to_string()))?;

        let mut config = Self::default();

        let url = if let Some((userinfo, rest)) = url.rsplit_once('@') {
            // Split userinfo into username:password per Redis URL convention.
            if let Some((username, password)) = userinfo.split_once(':') {
                if !username.is_empty() {
                    config.username = Some(username.to_string());
                }
                config.password = Some(password.to_string());
            } else {
                // No colon: treat the entire userinfo as the password.
                config.password = Some(userinfo.to_string());
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

        Ok(config)
    }
}

#[derive(Debug)]
struct RedisConnection {
    stream: TcpStream,
    read_buf: RespReadBuffer,
    config: RedisConfig,
    initialized: bool,
}

impl RedisConnection {
    async fn connect(config: RedisConfig) -> Result<Self, RedisError> {
        let addr = format!("{}:{}", config.host, config.port);
        let stream = TcpStream::connect(addr).await?;
        Ok(Self {
            stream,
            read_buf: RespReadBuffer::new(),
            config,
            initialized: false,
        })
    }

    async fn ensure_initialized(&mut self, cx: &Cx) -> Result<(), RedisError> {
        if self.initialized {
            return Ok(());
        }

        cx.trace("redis: initializing connection (AUTH/SELECT)");

        let password = self.config.password.clone();
        let username = self.config.username.clone();
        if let Some(password) = password {
            // Redis 6+ ACL: AUTH username password; pre-6: AUTH password.
            let resp = if let Some(ref username) = username {
                self.exec_no_init(cx, &[b"AUTH", username.as_bytes(), password.as_bytes()])
                    .await?
            } else {
                self.exec_no_init(cx, &[b"AUTH", password.as_bytes()])
                    .await?
            };
            if !resp.is_ok() {
                return Err(RedisError::Protocol(format!(
                    "AUTH expected +OK, got {resp:?}"
                )));
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

    async fn read_response(&mut self, cx: &Cx) -> Result<RespValue, RedisError> {
        loop {
            cx.checkpoint().map_err(|_| RedisError::Cancelled)?;

            if let Some((value, consumed)) = RespValue::try_decode(self.read_buf.available())? {
                self.read_buf.consume(consumed);
                return Ok(value);
            }

            if self.read_buf.len() > MAX_RESP_FRAME_SIZE {
                return Err(RedisError::Protocol(format!(
                    "RESP frame exceeds limit ({MAX_RESP_FRAME_SIZE} bytes)"
                )));
            }

            let mut tmp = [0u8; 4096];
            let n = std::future::poll_fn(|task_cx| {
                let mut read_buf = ReadBuf::new(&mut tmp);
                match Pin::new(&mut self.stream).poll_read(task_cx, &mut read_buf) {
                    std::task::Poll::Pending => std::task::Poll::Pending,
                    std::task::Poll::Ready(Ok(())) => {
                        std::task::Poll::Ready(Ok(read_buf.filled().len()))
                    }
                    std::task::Poll::Ready(Err(e)) => std::task::Poll::Ready(Err(e)),
                }
            })
            .await?;
            if n == 0 {
                return Err(RedisError::Io(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "redis connection closed",
                )));
            }
            self.read_buf.extend(&tmp[..n]);
        }
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

/// Redis client (Phase 1: TCP + RESP decode + pooling).
pub struct RedisClient {
    config: RedisConfig,
    pool: GenericPool<RedisConnection, RedisFactory>,
}

impl fmt::Debug for RedisClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RedisClient")
            .field("host", &self.config.host)
            .field("port", &self.config.port)
            .field("database", &self.config.database)
            .field("has_password", &self.config.password.is_some())
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

        let factory: RedisFactory = Box::new(move || {
            let config = config_for_factory.clone();
            Box::pin(async move { RedisConnection::connect(config).await })
        });

        let pool = GenericPool::new(factory, PoolConfig::with_max_size(10));

        Ok(Self { config, pool })
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

    /// Execute a raw command (string args).
    pub async fn cmd(&self, cx: &Cx, args: &[&str]) -> Result<RespValue, RedisError> {
        let mut bytes: Vec<&[u8]> = Vec::with_capacity(args.len());
        for s in args {
            bytes.push(s.as_bytes());
        }
        self.cmd_bytes(cx, &bytes).await
    }

    /// Execute a raw command (byte args).
    pub async fn cmd_bytes(&self, cx: &Cx, args: &[&[u8]]) -> Result<RespValue, RedisError> {
        let mut conn = self.acquire(cx).await?;
        match conn.exec(cx, args).await {
            Ok(resp) => Ok(resp),
            Err(e @ RedisError::Redis(_)) => Err(e),
            Err(e) => {
                conn.discard();
                Err(e)
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

        let mut args: Vec<&[u8]> = Vec::with_capacity(keys.len() + 1);
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

        let mut args: Vec<&[u8]> = Vec::with_capacity(fields.len() + 2);
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
    pub async fn watch(&self, cx: &Cx, keys: &[&str]) -> Result<(), RedisError> {
        if keys.is_empty() {
            return Err(RedisError::Protocol(
                "WATCH requires at least one key".to_string(),
            ));
        }

        let mut args: Vec<&[u8]> = Vec::with_capacity(keys.len() + 1);
        args.push(b"WATCH");
        for key in keys {
            args.push(key.as_bytes());
        }
        let resp = self.cmd_bytes(cx, &args).await?;
        expect_ok_response(&resp, "WATCH")
    }

    /// Clear all watched keys on the connection selected for this command.
    ///
    /// This mirrors Redis command semantics but does not guarantee the call is
    /// made on the same pooled connection previously used for `WATCH`.
    pub async fn unwatch(&self, cx: &Cx) -> Result<(), RedisError> {
        let resp = self.cmd_bytes(cx, &[b"UNWATCH"]).await?;
        expect_ok_response(&resp, "UNWATCH")
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

/// A Redis command pipeline.
///
/// Pipelines batch multiple commands onto a *single* connection, sending the
/// requests back-to-back and then reading the same number of responses in
/// order.
///
/// Notes:
/// - If any command yields a RESP `-ERR ...` response, `exec()` returns
///   `RedisError::Redis` and discards the underlying connection.
/// - If an I/O error occurs mid-pipeline, the connection is discarded because
///   its read/write state is no longer reliable.
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

    /// Execute the pipeline and return all responses.
    pub async fn exec(self, cx: &Cx) -> Result<Vec<RespValue>, RedisError> {
        let mut conn = self.client.acquire(cx).await?;

        // Ensure AUTH/SELECT have been run on this connection.
        if let Err(e) = conn.ensure_initialized(cx).await {
            conn.discard();
            return Err(e);
        }

        // Write all commands in one go to reduce syscalls.
        let total_len: usize = self.encoded.iter().map(Vec::len).sum();
        let mut combined = Vec::with_capacity(total_len);
        for cmd in &self.encoded {
            combined.extend_from_slice(cmd);
        }

        cx.checkpoint().map_err(|_| RedisError::Cancelled)?;
        if let Err(e) = conn.stream.write_all(&combined).await {
            conn.discard();
            return Err(RedisError::Io(e));
        }
        if let Err(e) = conn.stream.flush().await {
            conn.discard();
            return Err(RedisError::Io(e));
        }

        let mut out = Vec::with_capacity(self.encoded.len());
        for _ in 0..self.encoded.len() {
            let resp = match conn.read_response(cx).await {
                Ok(resp) => resp,
                Err(e) => {
                    conn.discard();
                    return Err(e);
                }
            };
            match resp {
                RespValue::Error(msg) => {
                    conn.discard();
                    return Err(RedisError::Redis(msg));
                }
                other => out.push(other),
            }
        }

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
        let mut conn = client.acquire(cx).await?;
        if let Err(e) = conn.ensure_initialized(cx).await {
            conn.discard();
            return Err(e);
        }

        let resp = match conn.exec_no_init(cx, &[b"MULTI"]).await {
            Ok(resp) => resp,
            Err(e) => {
                conn.discard();
                return Err(e);
            }
        };
        if let Err(e) = expect_ok_response(&resp, "MULTI") {
            conn.discard();
            return Err(e);
        }

        Ok(Self {
            conn: Some(conn),
            queued_commands: 0,
            finished: false,
        })
    }

    fn conn_mut(&mut self) -> Result<&mut PooledResource<RedisConnection>, RedisError> {
        self.conn
            .as_mut()
            .ok_or_else(|| RedisError::Protocol("transaction already finished".to_string()))
    }

    fn discard_connection(&mut self) {
        if let Some(conn) = self.conn.take() {
            conn.discard();
        }
        self.finished = true;
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
    pub async fn cmd_bytes(&mut self, cx: &Cx, args: &[&[u8]]) -> Result<(), RedisError> {
        if self.finished {
            return Err(RedisError::Protocol(
                "cannot queue command after transaction completion".to_string(),
            ));
        }

        if let Err(e) = self.conn_mut()?.write_command(cx, args).await {
            self.discard_connection();
            return Err(e);
        }

        let resp = match self.conn_mut()?.read_response(cx).await {
            Ok(resp) => resp,
            Err(e) => {
                self.discard_connection();
                return Err(e);
            }
        };

        match resp {
            RespValue::SimpleString(s) if s == "QUEUED" => {
                self.queued_commands = self.queued_commands.saturating_add(1);
                Ok(())
            }
            RespValue::Error(msg) => {
                self.discard_connection();
                Err(RedisError::Redis(msg))
            }
            other => {
                self.discard_connection();
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
        let mut conn = self.conn.take().ok_or_else(|| {
            RedisError::Protocol("cannot EXEC: transaction already finished".to_string())
        })?;
        self.finished = true;

        let resp = match conn.exec_no_init(cx, &[b"EXEC"]).await {
            Ok(resp) => resp,
            Err(e) => {
                conn.discard();
                return Err(e);
            }
        };

        match resp {
            RespValue::Array(Some(values)) => Ok(values),
            RespValue::Array(None) => Err(RedisError::Redis(
                "EXEC returned null (WATCH condition failed)".to_string(),
            )),
            other => {
                conn.discard();
                Err(RedisError::Protocol(format!(
                    "EXEC expected array reply, got {other:?}"
                )))
            }
        }
    }

    /// Abort the transaction with `DISCARD`.
    pub async fn discard(mut self, cx: &Cx) -> Result<(), RedisError> {
        let mut conn = self.conn.take().ok_or_else(|| {
            RedisError::Protocol("cannot DISCARD: transaction already finished".to_string())
        })?;
        self.finished = true;

        let resp = match conn.exec_no_init(cx, &[b"DISCARD"]).await {
            Ok(resp) => resp,
            Err(e) => {
                conn.discard();
                return Err(e);
            }
        };
        expect_ok_response(&resp, "DISCARD")
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
}

impl RedisPubSub {
    async fn connect(cx: &Cx, config: RedisConfig) -> Result<Self, RedisError> {
        let mut conn = RedisConnection::connect(config.clone()).await?;
        conn.ensure_initialized(cx).await?;
        Ok(Self {
            conn,
            config,
            channels: Vec::new(),
            patterns: Vec::new(),
            pending_events: VecDeque::new(),
        })
    }

    fn push_pending_event(&mut self, event: PubSubEvent) {
        const MAX_PENDING_EVENTS: usize = 4096;
        if self.pending_events.len() < MAX_PENDING_EVENTS {
            self.pending_events.push_back(event);
        }
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
            other => {
                return Err(RedisError::Protocol(format!(
                    "pubsub expected array event, got {other:?}"
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

    async fn read_next_event(&mut self, cx: &Cx) -> Result<PubSubEvent, RedisError> {
        let response = self.conn.read_response(cx).await?;
        Self::parse_event(response)
    }

    /// Subscribe to one or more channels.
    pub async fn subscribe(&mut self, cx: &Cx, channels: &[&str]) -> Result<(), RedisError> {
        if channels.is_empty() {
            return Err(RedisError::Protocol(
                "SUBSCRIBE requires at least one channel".to_string(),
            ));
        }

        let mut args: Vec<&[u8]> = Vec::with_capacity(channels.len() + 1);
        args.push(b"SUBSCRIBE");
        for channel in channels {
            args.push(channel.as_bytes());
        }
        self.conn.write_command(cx, &args).await?;

        let mut acks_remaining = channels.len();
        while acks_remaining > 0 {
            let event = self.read_next_event(cx).await?;
            match event {
                PubSubEvent::Subscription {
                    kind: PubSubSubscriptionKind::Subscribe,
                    channel,
                    ..
                } => {
                    Self::track_subscribe(&mut self.channels, &channel);
                    acks_remaining -= 1;
                }
                // Buffer interleaved messages from existing subscriptions
                // so they aren't silently dropped while waiting for acks.
                other => self.push_pending_event(other),
            }
        }

        Ok(())
    }

    /// Subscribe to one or more glob-style patterns.
    pub async fn psubscribe(&mut self, cx: &Cx, patterns: &[&str]) -> Result<(), RedisError> {
        if patterns.is_empty() {
            return Err(RedisError::Protocol(
                "PSUBSCRIBE requires at least one pattern".to_string(),
            ));
        }

        let mut args: Vec<&[u8]> = Vec::with_capacity(patterns.len() + 1);
        args.push(b"PSUBSCRIBE");
        for pattern in patterns {
            args.push(pattern.as_bytes());
        }
        self.conn.write_command(cx, &args).await?;

        let mut acks_remaining = patterns.len();
        while acks_remaining > 0 {
            let event = self.read_next_event(cx).await?;
            match event {
                PubSubEvent::Subscription {
                    kind: PubSubSubscriptionKind::PatternSubscribe,
                    channel,
                    ..
                } => {
                    Self::track_subscribe(&mut self.patterns, &channel);
                    acks_remaining -= 1;
                }
                other => self.push_pending_event(other),
            }
        }

        Ok(())
    }

    /// Unsubscribe from channels.
    ///
    /// Passing an empty slice unsubscribes from all channels currently tracked.
    pub async fn unsubscribe(&mut self, cx: &Cx, channels: &[&str]) -> Result<(), RedisError> {
        if channels.is_empty() && self.channels.is_empty() {
            return Ok(());
        }

        let mut args: Vec<&[u8]> = Vec::with_capacity(channels.len() + 1);
        args.push(b"UNSUBSCRIBE");
        for channel in channels {
            args.push(channel.as_bytes());
        }
        self.conn.write_command(cx, &args).await?;

        let mut acks_remaining = if channels.is_empty() {
            self.channels.len()
        } else {
            channels.len()
        };
        while acks_remaining > 0 {
            let event = self.read_next_event(cx).await?;
            match event {
                PubSubEvent::Subscription {
                    kind: PubSubSubscriptionKind::Unsubscribe,
                    channel,
                    ..
                } => {
                    Self::untrack_subscribe(&mut self.channels, &channel);
                    acks_remaining -= 1;
                }
                other => self.push_pending_event(other),
            }
        }
        Ok(())
    }

    /// Unsubscribe from patterns.
    ///
    /// Passing an empty slice unsubscribes from all patterns currently tracked.
    pub async fn punsubscribe(&mut self, cx: &Cx, patterns: &[&str]) -> Result<(), RedisError> {
        if patterns.is_empty() && self.patterns.is_empty() {
            return Ok(());
        }

        let mut args: Vec<&[u8]> = Vec::with_capacity(patterns.len() + 1);
        args.push(b"PUNSUBSCRIBE");
        for pattern in patterns {
            args.push(pattern.as_bytes());
        }
        self.conn.write_command(cx, &args).await?;

        let mut acks_remaining = if patterns.is_empty() {
            self.patterns.len()
        } else {
            patterns.len()
        };
        while acks_remaining > 0 {
            let event = self.read_next_event(cx).await?;
            match event {
                PubSubEvent::Subscription {
                    kind: PubSubSubscriptionKind::PatternUnsubscribe,
                    channel,
                    ..
                } => {
                    Self::untrack_subscribe(&mut self.patterns, &channel);
                    acks_remaining -= 1;
                }
                other => self.push_pending_event(other),
            }
        }
        Ok(())
    }

    /// Receive the next Pub/Sub event on this connection.
    pub async fn next_event(&mut self, cx: &Cx) -> Result<PubSubEvent, RedisError> {
        if let Some(event) = self.pending_events.pop_front() {
            return Ok(event);
        }
        self.read_next_event(cx).await
    }

    /// PING the Pub/Sub connection.
    ///
    /// Redis returns a `pong` event while subscribed.
    pub async fn ping(&mut self, cx: &Cx, payload: Option<&[u8]>) -> Result<(), RedisError> {
        if let Some(payload) = payload {
            self.conn.write_command(cx, &[b"PING", payload]).await?;
        } else {
            self.conn.write_command(cx, &[b"PING"]).await?;
        }
        // Loop until we receive PONG, buffering any interleaved events so a
        // liveness check cannot silently drop real messages. Cap the buffer
        // to prevent unbounded growth under high publish throughput.
        loop {
            match self.read_next_event(cx).await? {
                PubSubEvent::Pong(_) => return Ok(()),
                event @ (PubSubEvent::Message(_) | PubSubEvent::Subscription { .. }) => {
                    self.push_pending_event(event);
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

        let mut conn = RedisConnection::connect(self.config.clone()).await?;
        conn.ensure_initialized(cx).await?;
        self.conn = conn;
        self.channels.clear();
        self.patterns.clear();
        self.pending_events.clear();

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::{assert_completes_within, run_test_with_cx};
    use std::io::{Read, Write};
    use std::net::TcpListener as StdTcpListener;
    use std::thread;

    fn read_resp_frame(stream: &mut std::net::TcpStream) -> RespValue {
        let mut buf = Vec::new();
        let mut chunk = [0u8; 1024];
        loop {
            if let Some((value, consumed)) =
                RespValue::try_decode(&buf).expect("test server should decode RESP command")
            {
                assert_eq!(
                    consumed,
                    buf.len(),
                    "test server expected exactly one RESP frame per phase"
                );
                return value;
            }
            let n = stream.read(&mut chunk).expect("read client command");
            assert!(n > 0, "client closed before sending full RESP command");
            buf.extend_from_slice(&chunk[..n]);
        }
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
}
