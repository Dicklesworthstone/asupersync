//! Redis client with RESP protocol and Cx integration.
//!
//! This module provides a pure Rust Redis client implementing the RESP
//! (REdis Serialization Protocol) with Cx integration for cancel-correct
//! command execution.

use crate::cx::Cx;
use crate::io::{AsyncRead, AsyncWriteExt, ReadBuf};
use crate::net::TcpStream;
use crate::sync::{GenericPool, Pool as _, PoolConfig, PoolError, PooledResource};
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
                buf.extend_from_slice(s.as_bytes());
                buf.extend_from_slice(b"\r\n");
            }
            Self::Error(e) => {
                buf.push(b'-');
                buf.extend_from_slice(e.as_bytes());
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
        enum Decoded {
            NeedMore,
            Ok { value: RespValue, next: usize },
        }

        #[allow(clippy::too_many_lines)]
        fn decode_at(buf: &[u8], i: usize) -> Result<Decoded, RedisError> {
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
                    let end_crlf = end_data + 2;
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
                        match decode_at(buf, pos)? {
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

        match decode_at(buf, 0)? {
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
    /// Password for AUTH.
    pub password: Option<String>,
}

impl std::fmt::Debug for RedisConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RedisConfig")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("database", &self.database)
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

        let url = if let Some((password, rest)) = url.rsplit_once('@') {
            config.password = Some(password.to_string());
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
        if let Some(password) = password {
            let resp = self
                .exec_no_init(cx, &[b"AUTH", password.as_bytes()])
                .await?;
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
            let secs = u64_decimal_bytes(ttl.as_secs(), &mut tmp);
            let resp = self
                .cmd_bytes(cx, &[b"SET", key.as_bytes(), value, b"EX", secs])
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

    /// EXPIRE key seconds
    ///
    /// Returns true if the timeout was set, false if the key does not exist.
    pub async fn expire(&self, cx: &Cx, key: &str, ttl: Duration) -> Result<bool, RedisError> {
        let mut tmp = [0u8; 20];
        let secs = u64_decimal_bytes(ttl.as_secs(), &mut tmp);
        let resp = self
            .cmd_bytes(cx, &[b"EXPIRE", key.as_bytes(), secs])
            .await?;

        let n = resp
            .as_integer()
            .ok_or_else(|| RedisError::Protocol("EXPIRE did not return integer".to_string()))?;
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

#[cfg(test)]
mod tests {
    use super::*;

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
}
