//! NATS JetStream client with Cx integration.
//!
//! This module extends the NATS client with JetStream support for durable
//! streams, consumers, and exactly-once delivery semantics.
//!
//! # Overview
//!
//! JetStream is NATS' persistence layer providing:
//! - Durable message streams
//! - Pull and push consumers
//! - Exactly-once delivery with ack/nack
//! - Message deduplication
//!
//! # Example
//!
//! ```ignore
//! let client = NatsClient::connect(cx, "nats://localhost:4222").await?;
//! let js = JetStreamContext::new(client);
//!
//! // Create a stream
//! let stream = js.create_stream(cx, StreamConfig::new("ORDERS").subjects(&["orders.>"])).await?;
//!
//! // Publish with acknowledgement
//! let ack = js.publish(cx, "orders.new", b"order data").await?;
//!
//! // Create a consumer
//! let consumer = js.create_consumer(cx, "ORDERS", ConsumerConfig::new("processor")).await?;
//!
//! // Pull and process messages
//! for msg in consumer.pull(cx, 10).await? {
//!     process_order(&msg.payload);
//!     msg.ack(cx).await?;
//! }
//! ```

use super::nats::{Message, NatsClient, NatsError};
use crate::cx::Cx;
use crate::tracing_compat::warn;
use std::fmt;
use std::fmt::Write as _;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

/// JetStream-specific errors.
#[derive(Debug)]
pub enum JsError {
    /// Underlying NATS error.
    Nats(NatsError),
    /// JetStream API error response.
    Api {
        /// Error code returned by the JetStream API.
        code: u32,
        /// Human-readable error description.
        description: String,
    },
    /// Stream not found.
    StreamNotFound(String),
    /// Consumer not found.
    ConsumerNotFound {
        /// Stream name where the consumer is expected.
        stream: String,
        /// Consumer name that was not found.
        consumer: String,
    },
    /// Message not acknowledged.
    NotAcked,
    /// Invalid configuration.
    InvalidConfig(String),
    /// Parse error in API response.
    ParseError(String),
}

impl fmt::Display for JsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Nats(e) => write!(f, "JetStream NATS error: {e}"),
            Self::Api { code, description } => {
                write!(f, "JetStream API error {code}: {description}")
            }
            Self::StreamNotFound(name) => write!(f, "JetStream stream not found: {name}"),
            Self::ConsumerNotFound { stream, consumer } => {
                write!(f, "JetStream consumer not found: {stream}/{consumer}")
            }
            Self::NotAcked => write!(f, "JetStream message not acknowledged"),
            Self::InvalidConfig(msg) => write!(f, "JetStream invalid config: {msg}"),
            Self::ParseError(msg) => write!(f, "JetStream parse error: {msg}"),
        }
    }
}

impl std::error::Error for JsError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Nats(e) => Some(e),
            _ => None,
        }
    }
}

impl From<NatsError> for JsError {
    fn from(err: NatsError) -> Self {
        Self::Nats(err)
    }
}

/// Stream configuration.
#[derive(Debug, Clone)]
pub struct StreamConfig {
    /// Stream name (must be alphanumeric + dash/underscore).
    pub name: String,
    /// Subjects this stream captures.
    pub subjects: Vec<String>,
    /// Retention policy.
    pub retention: RetentionPolicy,
    /// Storage type.
    pub storage: StorageType,
    /// Maximum messages in stream.
    pub max_msgs: Option<i64>,
    /// Maximum bytes in stream.
    pub max_bytes: Option<i64>,
    /// Maximum age of messages.
    pub max_age: Option<Duration>,
    /// Maximum message size.
    pub max_msg_size: Option<i32>,
    /// Discard policy when limits reached.
    pub discard: DiscardPolicy,
    /// Number of replicas (for clustering).
    pub replicas: u32,
    /// Duplicate detection window.
    pub duplicate_window: Option<Duration>,
}

impl StreamConfig {
    /// Create a new stream configuration with the given name.
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            subjects: Vec::new(),
            retention: RetentionPolicy::Limits,
            storage: StorageType::File,
            max_msgs: None,
            max_bytes: None,
            max_age: None,
            max_msg_size: None,
            discard: DiscardPolicy::Old,
            replicas: 1,
            duplicate_window: None,
        }
    }

    /// Set subjects for this stream.
    #[must_use]
    pub fn subjects(mut self, subjects: &[&str]) -> Self {
        self.subjects = subjects.iter().map(|s| (*s).to_string()).collect();
        self
    }

    /// Set retention policy.
    #[must_use]
    pub fn retention(mut self, policy: RetentionPolicy) -> Self {
        self.retention = policy;
        self
    }

    /// Set storage type.
    #[must_use]
    pub fn storage(mut self, storage: StorageType) -> Self {
        self.storage = storage;
        self
    }

    /// Set maximum messages.
    #[must_use]
    pub fn max_messages(mut self, max: i64) -> Self {
        self.max_msgs = Some(max);
        self
    }

    /// Set maximum bytes.
    #[must_use]
    pub fn max_bytes(mut self, max: i64) -> Self {
        self.max_bytes = Some(max);
        self
    }

    /// Set maximum message age.
    #[must_use]
    pub fn max_age(mut self, age: Duration) -> Self {
        self.max_age = Some(age);
        self
    }

    /// Set replica count.
    #[must_use]
    pub fn replicas(mut self, count: u32) -> Self {
        self.replicas = count;
        self
    }

    /// Set duplicate detection window.
    #[must_use]
    pub fn duplicate_window(mut self, window: Duration) -> Self {
        self.duplicate_window = Some(window);
        self
    }

    /// Encode to JSON for API request.
    fn to_json(&self) -> String {
        let mut json = String::from("{");
        write!(&mut json, "\"name\":\"{}\"", self.name).expect("write to String");

        if !self.subjects.is_empty() {
            json.push_str(",\"subjects\":[");
            for (i, s) in self.subjects.iter().enumerate() {
                if i > 0 {
                    json.push(',');
                }
                write!(&mut json, "\"{s}\"").expect("write to String");
            }
            json.push(']');
        }

        write!(&mut json, ",\"retention\":\"{}\"", self.retention.as_str())
            .expect("write to String");
        write!(&mut json, ",\"storage\":\"{}\"", self.storage.as_str()).expect("write to String");
        write!(&mut json, ",\"discard\":\"{}\"", self.discard.as_str()).expect("write to String");
        write!(&mut json, ",\"num_replicas\":{}", self.replicas).expect("write to String");

        if let Some(max) = self.max_msgs {
            write!(&mut json, ",\"max_msgs\":{max}").expect("write to String");
        }
        if let Some(max) = self.max_bytes {
            write!(&mut json, ",\"max_bytes\":{max}").expect("write to String");
        }
        if let Some(age) = self.max_age {
            write!(&mut json, ",\"max_age\":{}", age.as_nanos()).expect("write to String");
        }
        if let Some(size) = self.max_msg_size {
            write!(&mut json, ",\"max_msg_size\":{size}").expect("write to String");
        }
        if let Some(window) = self.duplicate_window {
            write!(&mut json, ",\"duplicate_window\":{}", window.as_nanos())
                .expect("write to String");
        }

        json.push('}');
        json
    }
}

/// Retention policy for streams.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RetentionPolicy {
    /// Keep messages until limits are reached (default).
    #[default]
    Limits,
    /// Keep messages until acknowledged by all consumers.
    Interest,
    /// Keep messages until acknowledged by any consumer.
    WorkQueue,
}

impl RetentionPolicy {
    fn as_str(self) -> &'static str {
        match self {
            Self::Limits => "limits",
            Self::Interest => "interest",
            Self::WorkQueue => "workqueue",
        }
    }
}

/// Storage type for streams.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum StorageType {
    /// File-based storage (default, persistent).
    #[default]
    File,
    /// Memory-based storage (faster, not persistent).
    Memory,
}

impl StorageType {
    fn as_str(self) -> &'static str {
        match self {
            Self::File => "file",
            Self::Memory => "memory",
        }
    }
}

/// Discard policy when stream limits are reached.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DiscardPolicy {
    /// Discard old messages (default).
    #[default]
    Old,
    /// Discard new messages.
    New,
}

impl DiscardPolicy {
    fn as_str(self) -> &'static str {
        match self {
            Self::Old => "old",
            Self::New => "new",
        }
    }
}

/// Stream information returned by JetStream API.
#[derive(Debug, Clone)]
pub struct StreamInfo {
    /// Stream configuration.
    pub config: StreamConfig,
    /// Current state.
    pub state: StreamState,
}

/// Current state of a stream.
#[derive(Debug, Clone, Default)]
pub struct StreamState {
    /// Total messages in stream.
    pub messages: u64,
    /// Total bytes in stream.
    pub bytes: u64,
    /// First sequence number.
    pub first_seq: u64,
    /// Last sequence number.
    pub last_seq: u64,
    /// Number of consumers.
    pub consumer_count: u32,
}

/// Consumer configuration.
#[derive(Debug, Clone)]
pub struct ConsumerConfig {
    /// Consumer name (durable consumers).
    pub name: Option<String>,
    /// Durable name (deprecated, use name).
    pub durable_name: Option<String>,
    /// Delivery policy.
    pub deliver_policy: DeliverPolicy,
    /// Ack policy.
    pub ack_policy: AckPolicy,
    /// Ack wait timeout.
    pub ack_wait: Duration,
    /// Max deliveries before giving up.
    pub max_deliver: i64,
    /// Filter subject.
    pub filter_subject: Option<String>,
    /// Max ack pending.
    pub max_ack_pending: i64,
}

impl ConsumerConfig {
    /// Create a new consumer configuration.
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: Some(name.into()),
            durable_name: None,
            deliver_policy: DeliverPolicy::All,
            ack_policy: AckPolicy::Explicit,
            ack_wait: Duration::from_secs(30),
            max_deliver: -1,
            filter_subject: None,
            max_ack_pending: 1000,
        }
    }

    /// Create an ephemeral consumer (no name).
    #[must_use]
    pub fn ephemeral() -> Self {
        Self {
            name: None,
            durable_name: None,
            deliver_policy: DeliverPolicy::All,
            ack_policy: AckPolicy::Explicit,
            ack_wait: Duration::from_secs(30),
            max_deliver: -1,
            filter_subject: None,
            max_ack_pending: 1000,
        }
    }

    /// Set delivery policy.
    #[must_use]
    pub fn deliver_policy(mut self, policy: DeliverPolicy) -> Self {
        self.deliver_policy = policy;
        self
    }

    /// Set ack policy.
    #[must_use]
    pub fn ack_policy(mut self, policy: AckPolicy) -> Self {
        self.ack_policy = policy;
        self
    }

    /// Set ack wait timeout.
    #[must_use]
    pub fn ack_wait(mut self, wait: Duration) -> Self {
        self.ack_wait = wait;
        self
    }

    /// Set max deliveries.
    #[must_use]
    pub fn max_deliver(mut self, max: i64) -> Self {
        self.max_deliver = max;
        self
    }

    /// Set filter subject.
    #[must_use]
    pub fn filter_subject(mut self, subject: impl Into<String>) -> Self {
        self.filter_subject = Some(subject.into());
        self
    }

    /// Encode to JSON for API request.
    fn to_json(&self) -> String {
        let mut json = String::from("{");
        let mut parts = Vec::new();

        if let Some(ref name) = self.name {
            parts.push(format!("\"name\":\"{name}\""));
        }
        if let Some(ref durable) = self.durable_name {
            parts.push(format!("\"durable_name\":\"{durable}\""));
        }
        parts.push(format!(
            "\"deliver_policy\":\"{}\"",
            self.deliver_policy.as_str()
        ));
        parts.push(format!("\"ack_policy\":\"{}\"", self.ack_policy.as_str()));
        parts.push(format!("\"ack_wait\":{}", self.ack_wait.as_nanos()));
        parts.push(format!("\"max_deliver\":{}", self.max_deliver));
        parts.push(format!("\"max_ack_pending\":{}", self.max_ack_pending));
        if let Some(ref filter) = self.filter_subject {
            parts.push(format!("\"filter_subject\":\"{filter}\""));
        }

        json.push_str(&parts.join(","));
        json.push('}');
        json
    }
}

/// Delivery policy for consumers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DeliverPolicy {
    /// Deliver all messages (default).
    #[default]
    All,
    /// Deliver only new messages.
    New,
    /// Deliver from a specific sequence.
    ByStartSequence(u64),
    /// Deliver from last received.
    Last,
    /// Deliver from last per subject.
    LastPerSubject,
}

impl DeliverPolicy {
    fn as_str(self) -> &'static str {
        match self {
            Self::All => "all",
            Self::New => "new",
            Self::ByStartSequence(_) => "by_start_sequence",
            Self::Last => "last",
            Self::LastPerSubject => "last_per_subject",
        }
    }
}

/// Ack policy for consumers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AckPolicy {
    /// Require explicit ack (default).
    #[default]
    Explicit,
    /// No ack required.
    None,
    /// Ack all messages up to this one.
    All,
}

impl AckPolicy {
    fn as_str(self) -> &'static str {
        match self {
            Self::Explicit => "explicit",
            Self::None => "none",
            Self::All => "all",
        }
    }
}

/// Publish acknowledgement from JetStream.
#[derive(Debug, Clone)]
pub struct PubAck {
    /// Stream the message was stored in.
    pub stream: String,
    /// Sequence number in the stream.
    pub seq: u64,
    /// Whether this was a duplicate.
    pub duplicate: bool,
}

/// A message from JetStream with ack capabilities.
pub struct JsMessage {
    /// Original NATS message.
    pub subject: String,
    /// Message payload.
    pub payload: Vec<u8>,
    /// Stream sequence number.
    pub sequence: u64,
    /// Delivery count.
    pub delivered: u32,
    /// Reply subject for ack.
    reply_subject: String,
    /// Whether the message has been acked.
    acked: AtomicBool,
}

impl fmt::Debug for JsMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("JsMessage")
            .field("subject", &self.subject)
            .field("sequence", &self.sequence)
            .field("delivered", &self.delivered)
            .field("payload_len", &self.payload.len())
            .field("reply_subject", &self.reply_subject)
            .field("acked", &self.acked.load(Ordering::SeqCst))
            .finish()
    }
}

impl JsMessage {
    /// Check if the message has been acknowledged.
    pub fn is_acked(&self) -> bool {
        self.acked.load(Ordering::SeqCst)
    }
}

impl Drop for JsMessage {
    fn drop(&mut self) {
        if !self.acked.load(Ordering::SeqCst) {
            warn!(
                subject = %self.subject,
                sequence = self.sequence,
                "JetStream message dropped without ack/nack - will be redelivered"
            );
        }
    }
}

/// JetStream context for stream and consumer operations.
pub struct JetStreamContext {
    client: NatsClient,
    prefix: String,
}

impl fmt::Debug for JetStreamContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("JetStreamContext")
            .field("prefix", &self.prefix)
            .finish_non_exhaustive()
    }
}

impl JetStreamContext {
    /// Create a new JetStream context from a NATS client.
    pub fn new(client: NatsClient) -> Self {
        Self {
            client,
            prefix: "$JS.API".to_string(),
        }
    }

    /// Create with a custom API prefix (for account isolation).
    pub fn with_prefix(client: NatsClient, prefix: impl Into<String>) -> Self {
        Self {
            client,
            prefix: prefix.into(),
        }
    }

    /// Create or update a stream.
    pub async fn create_stream(
        &mut self,
        cx: &Cx,
        config: StreamConfig,
    ) -> Result<StreamInfo, JsError> {
        cx.checkpoint().map_err(|_| NatsError::Cancelled)?;

        let subject = format!("{}.STREAM.CREATE.{}", self.prefix, config.name);
        let payload = config.to_json();

        let response = self
            .client
            .request(cx, &subject, payload.as_bytes())
            .await?;

        Self::parse_stream_info(&response.payload)
    }

    /// Get information about a stream.
    pub async fn get_stream(&mut self, cx: &Cx, name: &str) -> Result<StreamInfo, JsError> {
        cx.checkpoint().map_err(|_| NatsError::Cancelled)?;

        let subject = format!("{}.STREAM.INFO.{}", self.prefix, name);
        let response = self.client.request(cx, &subject, b"").await?;

        Self::parse_stream_info(&response.payload)
    }

    /// Delete a stream.
    pub async fn delete_stream(&mut self, cx: &Cx, name: &str) -> Result<(), JsError> {
        cx.checkpoint().map_err(|_| NatsError::Cancelled)?;

        let subject = format!("{}.STREAM.DELETE.{}", self.prefix, name);
        let response = self.client.request(cx, &subject, b"").await?;

        // Check for error in response
        let response_str = String::from_utf8_lossy(&response.payload);
        if response_str.contains("\"error\"") {
            return Err(Self::parse_api_error(&response_str));
        }

        Ok(())
    }

    /// Publish a message to a stream with acknowledgement.
    pub async fn publish(
        &mut self,
        cx: &Cx,
        subject: &str,
        payload: &[u8],
    ) -> Result<PubAck, JsError> {
        cx.checkpoint().map_err(|_| NatsError::Cancelled)?;

        // JetStream publishes go to regular subjects, ack comes via reply
        let response = self.client.request(cx, subject, payload).await?;
        Self::parse_pub_ack(&response.payload)
    }

    /// Publish with a message ID for deduplication.
    pub async fn publish_with_id(
        &mut self,
        cx: &Cx,
        subject: &str,
        msg_id: &str,
        payload: &[u8],
    ) -> Result<PubAck, JsError> {
        cx.checkpoint().map_err(|_| NatsError::Cancelled)?;

        // For deduplication, we need to send Nats-Msg-Id header
        // Since our NATS client doesn't support headers yet, we'll use
        // the API directly
        let api_subject = format!("{}.STREAM.MSG.PUT", self.prefix);
        let request = format!(
            "{{\"subject\":\"{subject}\",\"msg_id\":\"{msg_id}\",\"payload\":\"{}\"}}",
            base64_encode(payload)
        );

        let response = self
            .client
            .request(cx, &api_subject, request.as_bytes())
            .await?;
        Self::parse_pub_ack(&response.payload)
    }

    /// Create a consumer on a stream.
    pub async fn create_consumer(
        &mut self,
        cx: &Cx,
        stream: &str,
        config: ConsumerConfig,
    ) -> Result<Consumer, JsError> {
        cx.checkpoint().map_err(|_| NatsError::Cancelled)?;

        let consumer_name = config.name.clone().unwrap_or_default();
        let subject = if consumer_name.is_empty() {
            format!("{}.CONSUMER.CREATE.{}", self.prefix, stream)
        } else {
            format!(
                "{}.CONSUMER.CREATE.{}.{}",
                self.prefix, stream, consumer_name
            )
        };

        let payload = format!(
            "{{\"stream_name\":\"{stream}\",\"config\":{}}}",
            config.to_json()
        );
        let response = self
            .client
            .request(cx, &subject, payload.as_bytes())
            .await?;

        let response_str = String::from_utf8_lossy(&response.payload);
        if response_str.contains("\"error\"") {
            return Err(Self::parse_api_error(&response_str));
        }

        // Extract consumer name from response
        let name = extract_json_string_simple(&response_str, "name")
            .unwrap_or_else(|| consumer_name.clone());

        Ok(Consumer {
            stream: stream.to_string(),
            name,
            prefix: self.prefix.clone(),
        })
    }

    /// Get an existing consumer.
    pub async fn get_consumer(
        &mut self,
        cx: &Cx,
        stream: &str,
        consumer: &str,
    ) -> Result<Consumer, JsError> {
        cx.checkpoint().map_err(|_| NatsError::Cancelled)?;

        let subject = format!("{}.CONSUMER.INFO.{}.{}", self.prefix, stream, consumer);
        let response = self.client.request(cx, &subject, b"").await?;

        let response_str = String::from_utf8_lossy(&response.payload);
        if response_str.contains("\"error\"") {
            return Err(Self::parse_api_error(&response_str));
        }

        Ok(Consumer {
            stream: stream.to_string(),
            name: consumer.to_string(),
            prefix: self.prefix.clone(),
        })
    }

    /// Delete a consumer.
    pub async fn delete_consumer(
        &mut self,
        cx: &Cx,
        stream: &str,
        consumer: &str,
    ) -> Result<(), JsError> {
        cx.checkpoint().map_err(|_| NatsError::Cancelled)?;

        let subject = format!("{}.CONSUMER.DELETE.{}.{}", self.prefix, stream, consumer);
        let response = self.client.request(cx, &subject, b"").await?;

        let response_str = String::from_utf8_lossy(&response.payload);
        if response_str.contains("\"error\"") {
            return Err(Self::parse_api_error(&response_str));
        }

        Ok(())
    }

    /// Get the underlying NATS client (for direct operations).
    pub fn client(&mut self) -> &mut NatsClient {
        &mut self.client
    }

    fn parse_stream_info(payload: &[u8]) -> Result<StreamInfo, JsError> {
        let json = String::from_utf8_lossy(payload);

        if json.contains("\"error\"") {
            return Err(Self::parse_api_error(&json));
        }

        // Parse config from response
        let name = extract_json_string_simple(&json, "name")
            .ok_or_else(|| JsError::ParseError("missing stream name".to_string()))?;

        let state = StreamState {
            messages: extract_json_u64(&json, "messages").unwrap_or(0),
            bytes: extract_json_u64(&json, "bytes").unwrap_or(0),
            first_seq: extract_json_u64(&json, "first_seq").unwrap_or(0),
            last_seq: extract_json_u64(&json, "last_seq").unwrap_or(0),
            consumer_count: extract_json_u64(&json, "consumer_count").unwrap_or(0) as u32,
        };

        Ok(StreamInfo {
            config: StreamConfig::new(name),
            state,
        })
    }

    fn parse_pub_ack(payload: &[u8]) -> Result<PubAck, JsError> {
        let json = String::from_utf8_lossy(payload);

        if json.contains("\"error\"") {
            return Err(Self::parse_api_error(&json));
        }

        let stream = extract_json_string_simple(&json, "stream")
            .ok_or_else(|| JsError::ParseError("missing stream in PubAck".to_string()))?;
        let seq = extract_json_u64(&json, "seq")
            .ok_or_else(|| JsError::ParseError("missing seq in PubAck".to_string()))?;
        let duplicate = json.contains("\"duplicate\":true");

        Ok(PubAck {
            stream,
            seq,
            duplicate,
        })
    }

    fn parse_api_error(json: &str) -> JsError {
        let code = extract_json_u64(json, "code").unwrap_or(0) as u32;
        let description = extract_json_string_simple(json, "description")
            .unwrap_or_else(|| "unknown error".to_string());

        if code == 10059 {
            // Stream not found
            return JsError::StreamNotFound(description);
        }

        JsError::Api { code, description }
    }
}

/// A JetStream consumer for pulling messages.
pub struct Consumer {
    stream: String,
    name: String,
    prefix: String,
}

impl fmt::Debug for Consumer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Consumer")
            .field("stream", &self.stream)
            .field("name", &self.name)
            .field("prefix", &self.prefix)
            .finish()
    }
}

impl Consumer {
    /// Get the consumer name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Get the stream name.
    #[must_use]
    pub fn stream(&self) -> &str {
        &self.stream
    }

    /// Pull a batch of messages.
    pub async fn pull(
        &self,
        client: &mut NatsClient,
        cx: &Cx,
        batch: usize,
    ) -> Result<Vec<JsMessage>, JsError> {
        cx.checkpoint().map_err(|_| NatsError::Cancelled)?;

        let subject = format!(
            "{}.CONSUMER.MSG.NEXT.{}.{}",
            self.prefix, self.stream, self.name
        );
        let request = format!("{{\"batch\":{batch}}}");

        // Subscribe to get batch responses
        let mut sub = client
            .subscribe(cx, &format!("_INBOX.{}", random_id()))
            .await?;
        client
            .publish_request(cx, &subject, sub.subject(), request.as_bytes())
            .await?;

        let mut messages = Vec::with_capacity(batch);

        // Collect messages until we get batch or timeout
        for _ in 0..batch {
            match sub.next(cx).await? {
                Some(msg) => {
                    if let Some(js_msg) = Self::parse_js_message(msg) {
                        messages.push(js_msg);
                    } else {
                        break; // Status message or end
                    }
                }
                None => break,
            }
        }

        Ok(messages)
    }

    fn parse_js_message(msg: Message) -> Option<JsMessage> {
        // JetStream messages have metadata in headers (reply subject format)
        // Format: $JS.ACK.<stream>.<consumer>.<delivered>.<stream_seq>.<consumer_seq>.<timestamp>.<pending>
        let reply = msg.reply_to?;

        if !reply.starts_with("$JS.ACK.") {
            return None;
        }

        let parts: Vec<&str> = reply.split('.').collect();
        if parts.len() < 9 {
            return None;
        }

        let delivered: u32 = parts[4].parse().ok()?;
        let sequence: u64 = parts[5].parse().ok()?;

        Some(JsMessage {
            subject: msg.subject,
            payload: msg.payload,
            sequence,
            delivered,
            reply_subject: reply,
            acked: AtomicBool::new(false),
        })
    }
}

impl JsMessage {
    /// Acknowledge the message (marks as processed).
    pub async fn ack(&self, client: &mut NatsClient, cx: &Cx) -> Result<(), JsError> {
        cx.checkpoint().map_err(|_| NatsError::Cancelled)?;

        client.publish(cx, &self.reply_subject, b"+ACK").await?;
        self.acked.store(true, Ordering::SeqCst);
        Ok(())
    }

    /// Negative acknowledge (request redelivery).
    pub async fn nack(&self, client: &mut NatsClient, cx: &Cx) -> Result<(), JsError> {
        cx.checkpoint().map_err(|_| NatsError::Cancelled)?;

        client.publish(cx, &self.reply_subject, b"-NAK").await?;
        self.acked.store(true, Ordering::SeqCst);
        Ok(())
    }

    /// Acknowledge in progress (extend ack deadline).
    pub async fn in_progress(&self, client: &mut NatsClient, cx: &Cx) -> Result<(), JsError> {
        cx.checkpoint().map_err(|_| NatsError::Cancelled)?;

        client.publish(cx, &self.reply_subject, b"+WPI").await?;
        Ok(())
    }

    /// Terminate processing (do not redeliver).
    pub async fn term(&self, client: &mut NatsClient, cx: &Cx) -> Result<(), JsError> {
        cx.checkpoint().map_err(|_| NatsError::Cancelled)?;

        client.publish(cx, &self.reply_subject, b"+TERM").await?;
        self.acked.store(true, Ordering::SeqCst);
        Ok(())
    }
}

// Helper functions

fn extract_json_string_simple(json: &str, key: &str) -> Option<String> {
    let pattern = format!("\"{key}\":\"");
    let start = json.find(&pattern)? + pattern.len();
    let end = json[start..].find('"')? + start;
    Some(json[start..end].to_string())
}

fn extract_json_u64(json: &str, key: &str) -> Option<u64> {
    let pattern = format!("\"{key}\":");
    let start = json.find(&pattern)? + pattern.len();
    let rest = json[start..].trim_start();
    let end = rest
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(rest.len());
    rest[..end].parse().ok()
}

fn base64_encode(data: &[u8]) -> String {
    // Simple base64 encoding
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut result = String::new();

    for chunk in data.chunks(3) {
        let n = match chunk.len() {
            1 => (u32::from(chunk[0]) << 16, 2),
            2 => ((u32::from(chunk[0]) << 16) | (u32::from(chunk[1]) << 8), 3),
            3 => (
                (u32::from(chunk[0]) << 16) | (u32::from(chunk[1]) << 8) | u32::from(chunk[2]),
                4,
            ),
            _ => continue,
        };

        for i in 0..n.1 {
            let idx = ((n.0 >> (18 - 6 * i)) & 0x3F) as usize;
            result.push(ALPHABET[idx] as char);
        }
    }

    // Padding
    let padding = (3 - data.len() % 3) % 3;
    for _ in 0..padding {
        result.push('=');
    }

    result
}

fn random_id() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("{:016x}", nanos ^ u128::from(std::process::id()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stream_config_to_json() {
        let config = StreamConfig::new("TEST")
            .subjects(&["test.>"])
            .max_messages(1000)
            .replicas(1);

        let json = config.to_json();
        assert!(json.contains("\"name\":\"TEST\""));
        assert!(json.contains("\"subjects\":[\"test.>\"]"));
        assert!(json.contains("\"max_msgs\":1000"));
    }

    #[test]
    fn test_consumer_config_to_json() {
        let config = ConsumerConfig::new("my-consumer")
            .ack_policy(AckPolicy::Explicit)
            .filter_subject("orders.>");

        let json = config.to_json();
        assert!(json.contains("\"name\":\"my-consumer\""));
        assert!(json.contains("\"ack_policy\":\"explicit\""));
        assert!(json.contains("\"filter_subject\":\"orders.>\""));
    }

    #[test]
    fn test_ephemeral_consumer_config_to_json() {
        // Regression test: ephemeral consumers (no name) should not produce invalid JSON
        let config = ConsumerConfig::ephemeral();
        let json = config.to_json();

        // Should start with valid JSON object, not `{,`
        assert!(json.starts_with("{\"deliver_policy\""));
        assert!(!json.contains("{,"));
        assert!(json.contains("\"deliver_policy\":\"all\""));
        assert!(json.contains("\"ack_policy\":\"explicit\""));
    }

    #[test]
    fn test_retention_policy_str() {
        assert_eq!(RetentionPolicy::Limits.as_str(), "limits");
        assert_eq!(RetentionPolicy::Interest.as_str(), "interest");
        assert_eq!(RetentionPolicy::WorkQueue.as_str(), "workqueue");
    }

    #[test]
    fn test_storage_type_str() {
        assert_eq!(StorageType::File.as_str(), "file");
        assert_eq!(StorageType::Memory.as_str(), "memory");
    }

    #[test]
    fn test_ack_policy_str() {
        assert_eq!(AckPolicy::Explicit.as_str(), "explicit");
        assert_eq!(AckPolicy::None.as_str(), "none");
        assert_eq!(AckPolicy::All.as_str(), "all");
    }

    #[test]
    fn test_deliver_policy_str() {
        assert_eq!(DeliverPolicy::All.as_str(), "all");
        assert_eq!(DeliverPolicy::New.as_str(), "new");
        assert_eq!(DeliverPolicy::Last.as_str(), "last");
    }

    #[test]
    fn test_base64_encode() {
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_encode(b"f"), "Zg==");
        assert_eq!(base64_encode(b"fo"), "Zm8=");
        assert_eq!(base64_encode(b"foo"), "Zm9v");
        assert_eq!(base64_encode(b"foob"), "Zm9vYg==");
        assert_eq!(base64_encode(b"hello"), "aGVsbG8=");
    }

    #[test]
    fn test_extract_json_u64() {
        let json = r#"{"seq":12345,"messages":100}"#;
        assert_eq!(extract_json_u64(json, "seq"), Some(12345));
        assert_eq!(extract_json_u64(json, "messages"), Some(100));
        assert_eq!(extract_json_u64(json, "missing"), None);
    }

    #[test]
    fn test_js_error_display() {
        assert_eq!(
            format!("{}", JsError::StreamNotFound("TEST".to_string())),
            "JetStream stream not found: TEST"
        );
        assert_eq!(
            format!(
                "{}",
                JsError::Api {
                    code: 10059,
                    description: "not found".to_string()
                }
            ),
            "JetStream API error 10059: not found"
        );
        assert_eq!(
            format!("{}", JsError::NotAcked),
            "JetStream message not acknowledged"
        );
    }
}
