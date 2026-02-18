//! NATS client with Cx integration.
//!
//! This module provides a pure Rust NATS client implementing the NATS
//! text protocol with Cx integration for cancel-correct publish/subscribe.
//!
//! # Protocol Reference
//! Based on NATS protocol: <https://docs.nats.io/reference/reference-protocols/nats-protocol>
//!
//! # Example
//! ```ignore
//! let client = NatsClient::connect(cx, "nats://localhost:4222").await?;
//! client.publish(cx, "foo.bar", b"hello").await?;
//! let mut sub = client.subscribe(cx, "foo.*").await?;
//! let msg = sub.next(cx).await?;
//! ```

use crate::channel::mpsc;
use crate::cx::Cx;
use crate::io::{AsyncRead, AsyncWriteExt, ReadBuf};
use crate::net::TcpStream;
use crate::tracing_compat::warn;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::fmt;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::Poll;
use std::time::Duration;

/// Error type for NATS operations.
#[derive(Debug)]
pub enum NatsError {
    /// I/O error during communication.
    Io(io::Error),
    /// Protocol error (malformed NATS message).
    Protocol(String),
    /// Server returned an error response (-ERR).
    Server(String),
    /// Invalid URL format.
    InvalidUrl(String),
    /// Operation cancelled.
    Cancelled,
    /// Connection closed.
    Closed,
    /// Subscription not found.
    SubscriptionNotFound(u64),
    /// Connection not established.
    NotConnected,
}

impl fmt::Display for NatsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "NATS I/O error: {e}"),
            Self::Protocol(msg) => write!(f, "NATS protocol error: {msg}"),
            Self::Server(msg) => write!(f, "NATS server error: {msg}"),
            Self::InvalidUrl(url) => write!(f, "Invalid NATS URL: {url}"),
            Self::Cancelled => write!(f, "NATS operation cancelled"),
            Self::Closed => write!(f, "NATS connection closed"),
            Self::SubscriptionNotFound(sid) => write!(f, "NATS subscription not found: {sid}"),
            Self::NotConnected => write!(f, "NATS not connected"),
        }
    }
}

impl std::error::Error for NatsError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for NatsError {
    fn from(err: io::Error) -> Self {
        Self::Io(err)
    }
}

/// Configuration for NATS client.
#[derive(Debug, Clone)]
pub struct NatsConfig {
    /// Host address.
    pub host: String,
    /// Port.
    pub port: u16,
    /// Optional username for authentication.
    pub user: Option<String>,
    /// Optional password for authentication.
    pub password: Option<String>,
    /// Optional auth token.
    pub token: Option<String>,
    /// Client name sent to server.
    pub name: Option<String>,
    /// Enable verbose mode (server echoes +OK for each command).
    pub verbose: bool,
    /// Enable pedantic mode (stricter protocol checking).
    pub pedantic: bool,
    /// Request timeout for request/reply pattern.
    pub request_timeout: Duration,
    /// Maximum payload size (default 1MB).
    pub max_payload: usize,
}

impl Default for NatsConfig {
    fn default() -> Self {
        Self {
            host: "127.0.0.1".to_string(),
            port: 4222,
            user: None,
            password: None,
            token: None,
            name: None,
            verbose: false,
            pedantic: false,
            request_timeout: Duration::from_secs(10),
            max_payload: 1_048_576, // 1MB
        }
    }
}

impl NatsConfig {
    /// Create config from a NATS URL.
    ///
    /// Format: `nats://[user:password@]host[:port]`
    pub fn from_url(url: &str) -> Result<Self, NatsError> {
        let url = url
            .strip_prefix("nats://")
            .ok_or_else(|| NatsError::InvalidUrl(url.to_string()))?;

        let mut config = Self::default();

        // Parse credentials if present
        let url = if let Some((creds, rest)) = url.split_once('@') {
            if let Some((user, pass)) = creds.split_once(':') {
                config.user = Some(user.to_string());
                config.password = Some(pass.to_string());
            } else {
                // Token-based auth
                config.token = Some(creds.to_string());
            }
            rest
        } else {
            url
        };

        // Parse host:port
        if let Some((host, port)) = url.split_once(':') {
            config.host = host.to_string();
            config.port = port
                .parse()
                .map_err(|_| NatsError::InvalidUrl(format!("invalid port: {port}")))?;
        } else if !url.is_empty() {
            config.host = url.to_string();
        }

        Ok(config)
    }
}

/// A message received from NATS.
#[derive(Debug, Clone)]
pub struct Message {
    /// Subject the message was published to.
    pub subject: String,
    /// Subscription ID that received this message.
    pub sid: u64,
    /// Optional reply-to subject for request/reply pattern.
    pub reply_to: Option<String>,
    /// Message payload.
    pub payload: Vec<u8>,
}

/// Server INFO message parsed fields.
#[derive(Debug, Clone, Default)]
pub struct ServerInfo {
    /// Server ID.
    pub server_id: String,
    /// Server name.
    pub server_name: String,
    /// Server version.
    pub version: String,
    /// Protocol version.
    pub proto: i32,
    /// Max payload size allowed.
    pub max_payload: usize,
    /// Whether TLS is required.
    pub tls_required: bool,
    /// Whether TLS is available.
    pub tls_available: bool,
    /// Connected URL.
    pub connect_urls: Vec<String>,
}

impl ServerInfo {
    /// Parse INFO JSON payload (minimal parser, no serde dependency).
    fn parse(json: &str) -> Self {
        let mut info = Self::default();

        // Simple JSON field extraction (no nested objects)
        if let Some(v) = extract_json_string(json, "server_id") {
            info.server_id = v;
        }
        if let Some(v) = extract_json_string(json, "server_name") {
            info.server_name = v;
        }
        if let Some(v) = extract_json_string(json, "version") {
            info.version = v;
        }
        if let Some(v) = extract_json_i64(json, "proto") {
            info.proto = v as i32;
        }
        if let Some(v) = extract_json_i64(json, "max_payload") {
            info.max_payload = usize::try_from(v).unwrap_or(0);
        }
        if let Some(v) = extract_json_bool(json, "tls_required") {
            info.tls_required = v;
        }
        if let Some(v) = extract_json_bool(json, "tls_available") {
            info.tls_available = v;
        }

        info
    }
}

fn extract_json_string(json: &str, key: &str) -> Option<String> {
    let pattern = format!("\"{key}\":\"");
    let start = json.find(&pattern)? + pattern.len();
    // Walk forward, respecting backslash escapes
    let slice = &json[start..];
    let mut chars = slice.char_indices();
    loop {
        match chars.next()? {
            (i, '"') => return Some(json[start..start + i].to_string()),
            (_, '\\') => {
                chars.next()?;
            }
            _ => {}
        }
    }
}

/// Escape a string for safe embedding in JSON values.
fn nats_json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => {
                use std::fmt::Write;
                write!(&mut out, "\\u{:04x}", c as u32).expect("write to String");
            }
            c => out.push(c),
        }
    }
    out
}

fn extract_json_i64(json: &str, key: &str) -> Option<i64> {
    let pattern = format!("\"{key}\":");
    let start = json.find(&pattern)? + pattern.len();
    let rest = json[start..].trim_start();
    let end = rest
        .find(|c: char| !c.is_ascii_digit() && c != '-')
        .unwrap_or(rest.len());
    rest[..end].parse().ok()
}

fn extract_json_bool(json: &str, key: &str) -> Option<bool> {
    let pattern = format!("\"{key}\":");
    let start = json.find(&pattern)? + pattern.len();
    let rest = json[start..].trim_start();
    if rest.starts_with("true") {
        Some(true)
    } else if rest.starts_with("false") {
        Some(false)
    } else {
        None
    }
}

/// Generate a random suffix for unique inbox subjects using capability-based entropy.
fn random_suffix(cx: &Cx) -> String {
    let hi = cx.random_u64();
    let lo = cx.random_u64();
    format!("{:016x}", hi ^ lo)
}

/// Internal read buffer for NATS protocol parsing.
#[derive(Debug)]
struct NatsReadBuffer {
    buf: Vec<u8>,
    pos: usize,
}

impl NatsReadBuffer {
    fn new() -> Self {
        Self {
            buf: Vec::new(),
            pos: 0,
        }
    }

    fn available(&self) -> &[u8] {
        &self.buf[self.pos..]
    }

    fn extend(&mut self, bytes: &[u8]) {
        self.buf.extend_from_slice(bytes);
    }

    fn consume(&mut self, n: usize) {
        self.pos = self.pos.saturating_add(n);
        // Compact buffer when we've consumed a lot
        if self.pos > 0 && (self.pos > 4096 && self.pos > (self.buf.len() / 2)) {
            self.buf.drain(..self.pos);
            self.pos = 0;
        }
    }

    fn find_crlf(&self) -> Option<usize> {
        let buf = self.available();
        (0..buf.len().saturating_sub(1)).find(|&i| buf[i] == b'\r' && buf[i + 1] == b'\n')
    }
}

/// NATS protocol message types.
#[derive(Debug)]
enum NatsMessage {
    /// Server INFO message.
    Info(ServerInfo),
    /// Server MSG message (subscription message).
    Msg(Message),
    /// Server +OK acknowledgement.
    Ok,
    /// Server -ERR error.
    Err(String),
    /// Server PING.
    Ping,
    /// Server PONG.
    Pong,
}

/// Internal subscription state.
struct SubscriptionState {
    subject: String,
    sender: mpsc::Sender<Message>,
}

/// Shared state between client and subscriptions.
struct SharedState {
    subscriptions: Mutex<HashMap<u64, SubscriptionState>>,
    server_info: Mutex<Option<ServerInfo>>,
    closed: std::sync::atomic::AtomicBool,
}

impl SharedState {
    fn new() -> Self {
        Self {
            subscriptions: Mutex::new(HashMap::new()),
            server_info: Mutex::new(None),
            closed: std::sync::atomic::AtomicBool::new(false),
        }
    }
}

/// NATS client with Cx integration.
pub struct NatsClient {
    config: NatsConfig,
    stream: TcpStream,
    read_buf: NatsReadBuffer,
    state: Arc<SharedState>,
    next_sid: AtomicU64,
    connected: bool,
}

impl fmt::Debug for NatsClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NatsClient")
            .field("host", &self.config.host)
            .field("port", &self.config.port)
            .field("connected", &self.connected)
            .finish_non_exhaustive()
    }
}

impl NatsClient {
    /// Connect to a NATS server.
    pub async fn connect(cx: &Cx, url: &str) -> Result<Self, NatsError> {
        cx.checkpoint().map_err(|_| NatsError::Cancelled)?;

        let config = NatsConfig::from_url(url)?;
        Self::connect_with_config(cx, config).await
    }

    /// Connect with explicit configuration.
    pub async fn connect_with_config(cx: &Cx, config: NatsConfig) -> Result<Self, NatsError> {
        cx.checkpoint().map_err(|_| NatsError::Cancelled)?;
        cx.trace(&format!(
            "nats: connecting to {}:{}",
            config.host, config.port
        ));

        let addr = format!("{}:{}", config.host, config.port);
        let stream = TcpStream::connect(addr).await?;

        let mut client = Self {
            config,
            stream,
            read_buf: NatsReadBuffer::new(),
            state: Arc::new(SharedState::new()),
            next_sid: AtomicU64::new(1),
            connected: false,
        };

        // Read initial INFO from server
        let info = client.read_info(cx).await?;
        *client.state.server_info.lock() = Some(info.clone());

        // Send CONNECT command
        client.send_connect(cx).await?;
        client.connected = true;

        cx.trace("nats: connection established");
        Ok(client)
    }

    /// Read the initial INFO message from server.
    async fn read_info(&mut self, cx: &Cx) -> Result<ServerInfo, NatsError> {
        loop {
            cx.checkpoint().map_err(|_| NatsError::Cancelled)?;

            if let Some(msg) = self.try_parse_message()? {
                match msg {
                    NatsMessage::Info(info) => return Ok(info),
                    NatsMessage::Err(e) => return Err(NatsError::Server(e)),
                    _ => {
                        return Err(NatsError::Protocol(
                            "expected INFO message from server".to_string(),
                        ));
                    }
                }
            }

            self.read_more().await?;
        }
    }

    /// Send CONNECT command to server.
    async fn send_connect(&mut self, cx: &Cx) -> Result<(), NatsError> {
        cx.checkpoint().map_err(|_| NatsError::Cancelled)?;

        // Build CONNECT JSON
        let mut connect = String::from("{");
        connect.push_str("\"verbose\":");
        connect.push_str(if self.config.verbose { "true" } else { "false" });
        connect.push_str(",\"pedantic\":");
        connect.push_str(if self.config.pedantic {
            "true"
        } else {
            "false"
        });
        connect.push_str(",\"lang\":\"rust\"");
        connect.push_str(",\"version\":\"0.1.0\"");
        connect.push_str(",\"protocol\":1");

        if let Some(ref name) = self.config.name {
            connect.push_str(",\"name\":\"");
            connect.push_str(&nats_json_escape(name));
            connect.push('"');
        }

        if let Some(ref user) = self.config.user {
            connect.push_str(",\"user\":\"");
            connect.push_str(&nats_json_escape(user));
            connect.push('"');
        }

        if let Some(ref pass) = self.config.password {
            connect.push_str(",\"pass\":\"");
            connect.push_str(&nats_json_escape(pass));
            connect.push('"');
        }

        if let Some(ref token) = self.config.token {
            connect.push_str(",\"auth_token\":\"");
            connect.push_str(&nats_json_escape(token));
            connect.push('"');
        }

        connect.push('}');

        let cmd = format!("CONNECT {connect}\r\n");
        self.stream.write_all(cmd.as_bytes()).await?;
        self.stream.flush().await?;

        // If verbose mode, wait for +OK
        if self.config.verbose {
            self.expect_ok(cx).await?;
        }

        Ok(())
    }

    /// Wait for +OK response.
    async fn expect_ok(&mut self, cx: &Cx) -> Result<(), NatsError> {
        loop {
            cx.checkpoint().map_err(|_| NatsError::Cancelled)?;

            if let Some(msg) = self.try_parse_message()? {
                match msg {
                    NatsMessage::Ok => return Ok(()),
                    NatsMessage::Err(e) => return Err(NatsError::Server(e)),
                    NatsMessage::Ping => {
                        // Respond to PING during handshake
                        self.stream.write_all(b"PONG\r\n").await?;
                        self.stream.flush().await?;
                    }
                    _ => {} // Ignore other messages during handshake
                }
            } else {
                self.read_more().await?;
            }
        }
    }

    /// Read more data from the stream.
    async fn read_more(&mut self) -> Result<(), NatsError> {
        let mut tmp = [0u8; 4096];
        let n = std::future::poll_fn(|task_cx| {
            let mut read_buf = ReadBuf::new(&mut tmp);
            match Pin::new(&mut self.stream).poll_read(task_cx, &mut read_buf) {
                Poll::Pending => Poll::Pending,
                Poll::Ready(Ok(())) => Poll::Ready(Ok(read_buf.filled().len())),
                Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            }
        })
        .await?;

        if n == 0 {
            return Err(NatsError::Closed);
        }

        self.read_buf.extend(&tmp[..n]);
        Ok(())
    }

    /// Try to parse a complete message from the buffer.
    fn try_parse_message(&mut self) -> Result<Option<NatsMessage>, NatsError> {
        let buf = self.read_buf.available();
        if buf.is_empty() {
            return Ok(None);
        }

        // Check message type by prefix
        if buf.starts_with(b"INFO ") {
            return self.parse_info();
        } else if buf.starts_with(b"MSG ") {
            return self.parse_msg();
        } else if buf.starts_with(b"+OK") {
            if buf.len() >= 4 && buf[3] == b'\r' && buf.get(4) == Some(&b'\n') {
                self.read_buf.consume(5);
                return Ok(Some(NatsMessage::Ok));
            } else if buf.len() < 5 {
                return Ok(None); // Need more data
            }
        } else if buf.starts_with(b"-ERR ") {
            return self.parse_err();
        } else if buf.starts_with(b"PING") {
            if buf.len() >= 6 && buf[4] == b'\r' && buf[5] == b'\n' {
                self.read_buf.consume(6);
                return Ok(Some(NatsMessage::Ping));
            } else if buf.len() < 6 {
                return Ok(None);
            }
        } else if buf.starts_with(b"PONG") {
            if buf.len() >= 6 && buf[4] == b'\r' && buf[5] == b'\n' {
                self.read_buf.consume(6);
                return Ok(Some(NatsMessage::Pong));
            } else if buf.len() < 6 {
                return Ok(None);
            }
        }

        // Wait for more data or report unknown
        if self.read_buf.find_crlf().is_none() {
            return Ok(None);
        }

        // Unknown message type
        let line_end = self.read_buf.find_crlf().unwrap();
        let line = String::from_utf8_lossy(&self.read_buf.available()[..line_end]);
        Err(NatsError::Protocol(format!("unknown message: {line}")))
    }

    /// Parse INFO message.
    fn parse_info(&mut self) -> Result<Option<NatsMessage>, NatsError> {
        let buf = self.read_buf.available();
        let Some(end) = self.read_buf.find_crlf() else {
            return Ok(None);
        };

        let line = std::str::from_utf8(&buf[..end])
            .map_err(|_| NatsError::Protocol("invalid UTF-8 in INFO".to_string()))?;

        let json = line
            .strip_prefix("INFO ")
            .ok_or_else(|| NatsError::Protocol("malformed INFO".to_string()))?;

        let info = ServerInfo::parse(json);
        self.read_buf.consume(end + 2);
        Ok(Some(NatsMessage::Info(info)))
    }

    /// Parse MSG message.
    fn parse_msg(&mut self) -> Result<Option<NatsMessage>, NatsError> {
        let buf = self.read_buf.available();
        let Some(header_end) = self.read_buf.find_crlf() else {
            return Ok(None);
        };

        let header = std::str::from_utf8(&buf[..header_end])
            .map_err(|_| NatsError::Protocol("invalid UTF-8 in MSG header".to_string()))?;

        // MSG <subject> <sid> [reply-to] <#bytes>
        let mut parts = header.split_whitespace();
        let _msg = parts.next(); // "MSG"
        let subject_str = parts
            .next()
            .ok_or_else(|| NatsError::Protocol(format!("malformed MSG header: {header}")))?;
        let sid_str = parts
            .next()
            .ok_or_else(|| NatsError::Protocol(format!("malformed MSG header: {header}")))?;
        let third = parts
            .next()
            .ok_or_else(|| NatsError::Protocol(format!("malformed MSG header: {header}")))?;
        let fourth = parts.next();

        let subject = subject_str.to_string();
        let sid: u64 = sid_str
            .parse()
            .map_err(|_| NatsError::Protocol(format!("invalid SID: {sid_str}")))?;

        let (reply_to, payload_len) = if let Some(len_str) = fourth {
            (
                Some(third.to_string()),
                len_str.parse::<usize>().map_err(|_| {
                    NatsError::Protocol(format!("invalid payload length: {len_str}"))
                })?,
            )
        } else {
            (
                None,
                third
                    .parse::<usize>()
                    .map_err(|_| NatsError::Protocol(format!("invalid payload length: {third}")))?,
            )
        };

        // Check if we have the full payload + trailing CRLF
        let payload_start = header_end + 2;
        let payload_end = payload_start + payload_len;
        let total_len = payload_end + 2; // +2 for trailing CRLF

        if buf.len() < total_len {
            return Ok(None); // Need more data
        }

        let payload = buf[payload_start..payload_end].to_vec();

        self.read_buf.consume(total_len);

        Ok(Some(NatsMessage::Msg(Message {
            subject,
            sid,
            reply_to,
            payload,
        })))
    }

    /// Parse -ERR message.
    fn parse_err(&mut self) -> Result<Option<NatsMessage>, NatsError> {
        let buf = self.read_buf.available();
        let Some(end) = self.read_buf.find_crlf() else {
            return Ok(None);
        };

        let line = std::str::from_utf8(&buf[..end])
            .map_err(|_| NatsError::Protocol("invalid UTF-8 in -ERR".to_string()))?;

        let msg = line
            .strip_prefix("-ERR ")
            .unwrap_or(line)
            .trim_matches('\'')
            .to_string();

        self.read_buf.consume(end + 2);
        Ok(Some(NatsMessage::Err(msg)))
    }

    /// Publish a message to a subject.
    pub async fn publish(
        &mut self,
        cx: &Cx,
        subject: &str,
        payload: &[u8],
    ) -> Result<(), NatsError> {
        cx.checkpoint().map_err(|_| NatsError::Cancelled)?;

        if !self.connected {
            return Err(NatsError::NotConnected);
        }

        if payload.len() > self.config.max_payload {
            return Err(NatsError::Protocol(format!(
                "payload too large: {} > {}",
                payload.len(),
                self.config.max_payload
            )));
        }

        let cmd = format!("PUB {subject} {}\r\n", payload.len());
        self.stream.write_all(cmd.as_bytes()).await?;
        self.stream.write_all(payload).await?;
        self.stream.write_all(b"\r\n").await?;
        self.stream.flush().await?;

        // Handle any pending server messages (like PING)
        self.handle_pending_messages(cx).await?;

        Ok(())
    }

    /// Publish a message with a reply-to subject.
    pub async fn publish_request(
        &mut self,
        cx: &Cx,
        subject: &str,
        reply_to: &str,
        payload: &[u8],
    ) -> Result<(), NatsError> {
        cx.checkpoint().map_err(|_| NatsError::Cancelled)?;

        if !self.connected {
            return Err(NatsError::NotConnected);
        }

        if payload.len() > self.config.max_payload {
            return Err(NatsError::Protocol(format!(
                "payload too large: {} > {}",
                payload.len(),
                self.config.max_payload
            )));
        }

        let cmd = format!("PUB {subject} {reply_to} {}\r\n", payload.len());
        self.stream.write_all(cmd.as_bytes()).await?;
        self.stream.write_all(payload).await?;
        self.stream.write_all(b"\r\n").await?;
        self.stream.flush().await?;

        Ok(())
    }

    /// Request/reply pattern: publish and wait for a single response.
    ///
    /// This creates a unique inbox subject, subscribes to it, publishes
    /// the request, and waits for the first response (or timeout).
    pub async fn request(
        &mut self,
        cx: &Cx,
        subject: &str,
        payload: &[u8],
    ) -> Result<Message, NatsError> {
        cx.checkpoint().map_err(|_| NatsError::Cancelled)?;

        if !self.connected {
            return Err(NatsError::NotConnected);
        }

        // Generate unique inbox subject
        let inbox = format!(
            "_INBOX.{}.{}",
            self.next_sid.load(Ordering::Relaxed),
            random_suffix(cx)
        );

        // Subscribe to inbox
        let mut sub = self.subscribe(cx, &inbox).await?;

        // Publish request with reply-to inbox
        self.publish_request(cx, subject, &inbox, payload).await?;

        // Wait for response with timeout
        let timeout = self.config.request_timeout;
        let start = std::time::Instant::now();

        loop {
            cx.checkpoint().map_err(|_| NatsError::Cancelled)?;

            // Check timeout
            if start.elapsed() > timeout {
                // Clean up subscription
                self.unsubscribe(cx, sub.sid()).await?;
                return Err(NatsError::Protocol("request timeout".to_string()));
            }

            // Try to read any pending messages
            self.read_more().await?;

            // Process messages looking for our reply
            loop {
                match self.try_parse_message()? {
                    Some(NatsMessage::Ping) => {
                        self.stream.write_all(b"PONG\r\n").await?;
                        self.stream.flush().await?;
                    }
                    Some(NatsMessage::Msg(m)) => {
                        if m.sid == sub.sid() {
                            // This is our reply - clean up and return
                            self.unsubscribe(cx, sub.sid()).await?;
                            return Ok(m);
                        }
                        // Dispatch to other subscriptions
                        self.dispatch_message(m);
                    }
                    Some(NatsMessage::Err(e)) => {
                        return Err(NatsError::Server(e));
                    }
                    Some(_) => {}
                    None => break,
                }
            }

            // Also check the subscription channel in case message was already dispatched
            if let Some(msg) = sub.try_next() {
                self.unsubscribe(cx, sub.sid()).await?;
                return Ok(msg);
            }
        }
    }

    /// Subscribe to a subject.
    ///
    /// Returns a `Subscription` that can be used to receive messages.
    pub async fn subscribe(&mut self, cx: &Cx, subject: &str) -> Result<Subscription, NatsError> {
        cx.checkpoint().map_err(|_| NatsError::Cancelled)?;

        if !self.connected {
            return Err(NatsError::NotConnected);
        }

        let sid = self.next_sid.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = mpsc::channel(256); // Bounded for backpressure

        // Register subscription
        {
            let mut subs = self.state.subscriptions.lock();
            subs.insert(
                sid,
                SubscriptionState {
                    subject: subject.to_string(),
                    sender: tx,
                },
            );
        }

        // Send SUB command
        let cmd = format!("SUB {subject} {sid}\r\n");
        self.stream.write_all(cmd.as_bytes()).await?;
        self.stream.flush().await?;

        cx.trace(&format!("nats: subscribed to {subject} (sid={sid})"));

        Ok(Subscription {
            sid,
            subject: subject.to_string(),
            rx,
            state: Arc::clone(&self.state),
        })
    }

    /// Subscribe with a queue group.
    pub async fn queue_subscribe(
        &mut self,
        cx: &Cx,
        subject: &str,
        queue_group: &str,
    ) -> Result<Subscription, NatsError> {
        cx.checkpoint().map_err(|_| NatsError::Cancelled)?;

        if !self.connected {
            return Err(NatsError::NotConnected);
        }

        let sid = self.next_sid.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = mpsc::channel(256);

        {
            let mut subs = self.state.subscriptions.lock();
            subs.insert(
                sid,
                SubscriptionState {
                    subject: subject.to_string(),
                    sender: tx,
                },
            );
        }

        let cmd = format!("SUB {subject} {queue_group} {sid}\r\n");
        self.stream.write_all(cmd.as_bytes()).await?;
        self.stream.flush().await?;

        Ok(Subscription {
            sid,
            subject: subject.to_string(),
            rx,
            state: Arc::clone(&self.state),
        })
    }

    /// Unsubscribe from a subscription.
    pub async fn unsubscribe(&mut self, cx: &Cx, sid: u64) -> Result<(), NatsError> {
        cx.checkpoint().map_err(|_| NatsError::Cancelled)?;

        // Remove from local state
        {
            let mut subs = self.state.subscriptions.lock();
            subs.remove(&sid);
        }

        // Send UNSUB command
        let cmd = format!("UNSUB {sid}\r\n");
        self.stream.write_all(cmd.as_bytes()).await?;
        self.stream.flush().await?;

        Ok(())
    }

    /// Send PING and wait for PONG.
    pub async fn ping(&mut self, cx: &Cx) -> Result<(), NatsError> {
        cx.checkpoint().map_err(|_| NatsError::Cancelled)?;

        self.stream.write_all(b"PING\r\n").await?;
        self.stream.flush().await?;

        // Wait for PONG
        loop {
            cx.checkpoint().map_err(|_| NatsError::Cancelled)?;

            if let Some(msg) = self.try_parse_message()? {
                match msg {
                    NatsMessage::Pong => return Ok(()),
                    NatsMessage::Err(e) => return Err(NatsError::Server(e)),
                    NatsMessage::Ping => {
                        self.stream.write_all(b"PONG\r\n").await?;
                        self.stream.flush().await?;
                    }
                    NatsMessage::Msg(m) => {
                        // Dispatch to subscription
                        self.dispatch_message(m);
                    }
                    _ => {}
                }
            } else {
                self.read_more().await?;
            }
        }
    }

    /// Handle any pending server messages (like PING).
    async fn handle_pending_messages(&mut self, cx: &Cx) -> Result<(), NatsError> {
        // Non-blocking check for pending messages
        loop {
            match self.try_parse_message()? {
                Some(NatsMessage::Ping) => {
                    self.stream.write_all(b"PONG\r\n").await?;
                    self.stream.flush().await?;
                }
                Some(NatsMessage::Msg(m)) => {
                    self.dispatch_message(m);
                }
                Some(NatsMessage::Err(e)) => {
                    cx.trace(&format!("nats: server error: {e}"));
                }
                Some(_) => {}
                None => break,
            }
        }
        Ok(())
    }

    /// Dispatch a message to the appropriate subscription.
    fn dispatch_message(&self, msg: Message) {
        let subs = self.state.subscriptions.lock();
        if let Some(sub) = subs.get(&msg.sid) {
            // Try to send; warn if channel is full (backpressure)
            if sub.sender.try_send(msg).is_err() {
                warn!(
                    subject = %sub.subject,
                    "NATS message dropped due to backpressure - consumer too slow"
                );
            }
        }
    }

    /// Process incoming messages and dispatch to subscriptions.
    /// Call this periodically if you have active subscriptions.
    pub async fn process(&mut self, cx: &Cx) -> Result<(), NatsError> {
        cx.checkpoint().map_err(|_| NatsError::Cancelled)?;

        // Read available data
        self.read_more().await?;

        // Process all complete messages
        loop {
            match self.try_parse_message()? {
                Some(NatsMessage::Ping) => {
                    self.stream.write_all(b"PONG\r\n").await?;
                    self.stream.flush().await?;
                }
                Some(NatsMessage::Msg(m)) => {
                    self.dispatch_message(m);
                }
                Some(NatsMessage::Err(e)) => {
                    return Err(NatsError::Server(e));
                }
                Some(_) => {}
                None => break,
            }
        }

        Ok(())
    }

    /// Close the connection.
    #[allow(clippy::unused_async)]
    pub async fn close(&mut self, cx: &Cx) -> Result<(), NatsError> {
        cx.checkpoint().map_err(|_| NatsError::Cancelled)?;

        self.state.closed.store(true, Ordering::Release);

        // Clear all subscriptions
        {
            let mut subs = self.state.subscriptions.lock();
            subs.clear();
        }

        self.connected = false;
        Ok(())
    }

    /// Get server info.
    pub fn server_info(&self) -> Option<ServerInfo> {
        self.state.server_info.lock().clone()
    }
}

/// A subscription to a NATS subject.
pub struct Subscription {
    sid: u64,
    subject: String,
    rx: mpsc::Receiver<Message>,
    state: Arc<SharedState>,
}

impl fmt::Debug for Subscription {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Subscription")
            .field("sid", &self.sid)
            .field("subject", &self.subject)
            .finish_non_exhaustive()
    }
}

impl Subscription {
    /// Get the subscription ID.
    #[must_use]
    pub fn sid(&self) -> u64 {
        self.sid
    }

    /// Get the subject this subscription is for.
    #[must_use]
    pub fn subject(&self) -> &str {
        &self.subject
    }

    /// Receive the next message. Cancellation-safe.
    pub async fn next(&mut self, cx: &Cx) -> Result<Option<Message>, NatsError> {
        cx.checkpoint().map_err(|_| NatsError::Cancelled)?;

        if self.state.closed.load(Ordering::Acquire) {
            return Ok(None);
        }

        match self.rx.recv(cx).await {
            Ok(msg) => Ok(Some(msg)),
            Err(mpsc::RecvError::Disconnected | mpsc::RecvError::Empty) => Ok(None),
            Err(mpsc::RecvError::Cancelled) => Err(NatsError::Cancelled),
        }
    }

    /// Try to receive a message without blocking.
    pub fn try_next(&mut self) -> Option<Message> {
        self.rx.try_recv().ok()
    }
}

impl Drop for Subscription {
    fn drop(&mut self) {
        // Remove from shared state
        let mut subs = self.state.subscriptions.lock();
        subs.remove(&self.sid);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_from_url_simple() {
        let config = NatsConfig::from_url("nats://localhost:4222").unwrap();
        assert_eq!(config.host, "localhost");
        assert_eq!(config.port, 4222);
        assert!(config.user.is_none());
        assert!(config.password.is_none());
    }

    #[test]
    fn test_config_from_url_with_auth() {
        let config = NatsConfig::from_url("nats://user:pass@localhost:4222").unwrap();
        assert_eq!(config.host, "localhost");
        assert_eq!(config.port, 4222);
        assert_eq!(config.user, Some("user".to_string()));
        assert_eq!(config.password, Some("pass".to_string()));
    }

    #[test]
    fn test_config_from_url_with_token() {
        let config = NatsConfig::from_url("nats://mytoken@localhost:4222").unwrap();
        assert_eq!(config.host, "localhost");
        assert_eq!(config.port, 4222);
        assert_eq!(config.token, Some("mytoken".to_string()));
    }

    #[test]
    fn test_config_from_url_default_port() {
        let config = NatsConfig::from_url("nats://localhost").unwrap();
        assert_eq!(config.host, "localhost");
        assert_eq!(config.port, 4222); // Default port
    }

    #[test]
    fn test_server_info_parse() {
        let json = r#"{"server_id":"id123","server_name":"test","version":"2.9.0","proto":1,"max_payload":1048576,"tls_required":false}"#;
        let info = ServerInfo::parse(json);
        assert_eq!(info.server_id, "id123");
        assert_eq!(info.server_name, "test");
        assert_eq!(info.version, "2.9.0");
        assert_eq!(info.proto, 1);
        assert_eq!(info.max_payload, 1_048_576);
        assert!(!info.tls_required);
    }

    #[test]
    fn test_extract_json_string() {
        let json = r#"{"name":"value","other":123}"#;
        assert_eq!(extract_json_string(json, "name"), Some("value".to_string()));
        assert_eq!(extract_json_string(json, "missing"), None);
    }

    #[test]
    fn test_extract_json_i64() {
        let json = r#"{"count":42,"neg":-5}"#;
        assert_eq!(extract_json_i64(json, "count"), Some(42));
        assert_eq!(extract_json_i64(json, "neg"), Some(-5));
        assert_eq!(extract_json_i64(json, "missing"), None);
    }

    #[test]
    fn test_extract_json_bool() {
        let json = r#"{"enabled":true,"disabled":false}"#;
        assert_eq!(extract_json_bool(json, "enabled"), Some(true));
        assert_eq!(extract_json_bool(json, "disabled"), Some(false));
        assert_eq!(extract_json_bool(json, "missing"), None);
    }

    #[test]
    fn test_config_invalid_url() {
        let result = NatsConfig::from_url("http://localhost:4222");
        assert!(matches!(result, Err(NatsError::InvalidUrl(_))));
    }

    #[test]
    fn test_config_invalid_port() {
        let result = NatsConfig::from_url("nats://localhost:notaport");
        assert!(matches!(result, Err(NatsError::InvalidUrl(_))));
    }

    #[test]
    fn test_nats_error_display() {
        assert_eq!(
            format!("{}", NatsError::Cancelled),
            "NATS operation cancelled"
        );
        assert_eq!(format!("{}", NatsError::Closed), "NATS connection closed");
        assert_eq!(format!("{}", NatsError::NotConnected), "NATS not connected");
        assert_eq!(
            format!("{}", NatsError::SubscriptionNotFound(42)),
            "NATS subscription not found: 42"
        );
        assert_eq!(
            format!("{}", NatsError::Server("auth error".to_string())),
            "NATS server error: auth error"
        );
        assert_eq!(
            format!("{}", NatsError::Protocol("parse error".to_string())),
            "NATS protocol error: parse error"
        );
        assert_eq!(
            format!("{}", NatsError::InvalidUrl("bad".to_string())),
            "Invalid NATS URL: bad"
        );
    }

    #[test]
    fn test_random_suffix_format() {
        let cx: Cx = Cx::for_testing();
        let s1 = random_suffix(&cx);
        let s2 = random_suffix(&cx);
        // Verify format is correct (16 hex chars)
        assert_eq!(s1.len(), 16);
        assert!(s1.chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(s2.len(), 16);
        assert!(s2.chars().all(|c| c.is_ascii_hexdigit()));
        // With deterministic entropy, successive calls should differ
        assert_ne!(s1, s2);
    }

    #[test]
    fn test_server_info_parse_minimal() {
        let json = "{}";
        let info = ServerInfo::parse(json);
        assert_eq!(info.server_id, "");
        assert_eq!(info.max_payload, 0);
        assert!(!info.tls_required);
    }

    #[test]
    fn test_server_info_parse_with_tls() {
        let json = r#"{"tls_required":true,"tls_available":true}"#;
        let info = ServerInfo::parse(json);
        assert!(info.tls_required);
        assert!(info.tls_available);
    }

    #[test]
    fn test_nats_config_default() {
        let config = NatsConfig::default();
        assert_eq!(config.host, "127.0.0.1");
        assert_eq!(config.port, 4222);
        assert!(config.user.is_none());
        assert!(config.password.is_none());
        assert!(config.token.is_none());
        assert!(!config.verbose);
        assert!(!config.pedantic);
        assert_eq!(config.max_payload, 1_048_576);
        assert_eq!(config.request_timeout, Duration::from_secs(10));
    }

    #[test]
    fn test_read_buffer_operations() {
        let mut buf = NatsReadBuffer::new();
        assert!(buf.available().is_empty());

        buf.extend(b"hello\r\n");
        assert_eq!(buf.available(), b"hello\r\n");
        assert_eq!(buf.find_crlf(), Some(5));

        buf.consume(7);
        assert!(buf.available().is_empty());
    }

    #[test]
    fn test_read_buffer_partial_crlf() {
        let mut buf = NatsReadBuffer::new();
        buf.extend(b"hello\r");
        assert_eq!(buf.find_crlf(), None); // Incomplete CRLF

        buf.extend(b"\n");
        assert_eq!(buf.find_crlf(), Some(5));
    }

    #[test]
    fn test_nats_json_escape_c1_control() {
        // C1 control U+0080 is 2 bytes in UTF-8 (0xC2, 0x80).
        // Must emit a single \u0080 escape, not per-byte \u00c2\u0080.
        let input = "\u{0080}";
        let escaped = nats_json_escape(input);
        assert_eq!(escaped, "\\u0080");
    }

    #[test]
    fn test_nats_json_escape_c0_control() {
        // C0 control U+0001 (SOH) is 1 byte in UTF-8.
        let escaped = nats_json_escape("\u{0001}");
        assert_eq!(escaped, "\\u0001");
    }

    #[test]
    fn test_nats_json_escape_common_chars() {
        assert_eq!(nats_json_escape(r#"hello"world"#), r#"hello\"world"#);
        assert_eq!(nats_json_escape("back\\slash"), "back\\\\slash");
        assert_eq!(nats_json_escape("new\nline"), "new\\nline");
        assert_eq!(nats_json_escape("plain"), "plain");
    }
}
