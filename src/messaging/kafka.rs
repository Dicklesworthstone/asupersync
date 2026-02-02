//! Kafka producer with Cx integration for cancel-correct message publishing.
//!
//! This module provides a Kafka producer with exactly-once semantics and
//! transactional support, integrated with the Asupersync `Cx` context for
//! proper cancellation handling.
//!
//! # Design
//!
//! The implementation wraps the rdkafka crate (when available) with a Cx
//! integration layer. In Phase 0, this provides the API shape as stubs.
//!
//! # Exactly-Once Semantics
//!
//! Kafka supports exactly-once via:
//! - Idempotent producers (deduplication via sequence numbers)
//! - Transactional producers (atomic batch commits)
//!
//! # Cancel-Correct Behavior
//!
//! - In-flight sends are tracked as obligations
//! - Cancellation waits for pending acks (with bounded timeout)
//! - Uncommitted transactions abort on cancellation

// Phase 0 stubs return errors immediately; async is for API consistency
// with eventual rdkafka integration.
#![allow(clippy::unused_async)]

use crate::cx::Cx;
use std::fmt;
use std::io;
use std::time::Duration;

#[cfg(feature = "kafka")]
use rdkafka::{
    client::ClientContext,
    config::ClientConfig,
    error::{KafkaError as RdKafkaError, RDKafkaErrorCode},
    message::{BorrowedMessage, DeliveryResult, Header, Message, OwnedHeaders},
    producer::{BaseRecord, Producer, ProducerContext, ThreadedProducer},
    util::Timeout,
};
#[cfg(feature = "kafka")]
use std::future::Future;
#[cfg(feature = "kafka")]
use std::pin::Pin;
#[cfg(feature = "kafka")]
use std::sync::{Arc, Mutex};
#[cfg(feature = "kafka")]
use std::task::{Context, Poll, Waker};

/// Error type for Kafka operations.
#[derive(Debug)]
pub enum KafkaError {
    /// I/O error during communication.
    Io(io::Error),
    /// Protocol error (malformed Kafka response).
    Protocol(String),
    /// Kafka broker returned an error.
    Broker(String),
    /// Producer queue is full.
    QueueFull,
    /// Message is too large.
    MessageTooLarge {
        /// Size of the message.
        size: usize,
        /// Maximum allowed size.
        max_size: usize,
    },
    /// Invalid topic name.
    InvalidTopic(String),
    /// Transaction error.
    Transaction(String),
    /// Operation cancelled.
    Cancelled,
    /// Configuration error.
    Config(String),
}

impl fmt::Display for KafkaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "Kafka I/O error: {e}"),
            Self::Protocol(msg) => write!(f, "Kafka protocol error: {msg}"),
            Self::Broker(msg) => write!(f, "Kafka broker error: {msg}"),
            Self::QueueFull => write!(f, "Kafka producer queue is full"),
            Self::MessageTooLarge { size, max_size } => {
                write!(f, "Kafka message too large: {size} bytes (max: {max_size})")
            }
            Self::InvalidTopic(topic) => write!(f, "Invalid Kafka topic: {topic}"),
            Self::Transaction(msg) => write!(f, "Kafka transaction error: {msg}"),
            Self::Cancelled => write!(f, "Kafka operation cancelled"),
            Self::Config(msg) => write!(f, "Kafka configuration error: {msg}"),
        }
    }
}

impl std::error::Error for KafkaError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for KafkaError {
    fn from(err: io::Error) -> Self {
        Self::Io(err)
    }
}

#[cfg(feature = "kafka")]
#[derive(Debug)]
struct KafkaContext;

#[cfg(feature = "kafka")]
impl ClientContext for KafkaContext {}

#[cfg(feature = "kafka")]
impl ProducerContext for KafkaContext {
    type DeliveryOpaque = Box<DeliverySender>;

    fn delivery(
        &self,
        delivery_result: &DeliveryResult<'_>,
        delivery_opaque: Self::DeliveryOpaque,
    ) {
        let mapped = map_delivery_result(delivery_result);
        delivery_opaque.complete(mapped);
    }
}

#[cfg(feature = "kafka")]
#[derive(Debug)]
struct DeliveryState {
    value: Option<Result<RecordMetadata, KafkaError>>,
    waker: Option<Waker>,
    closed: bool,
}

#[cfg(feature = "kafka")]
impl DeliveryState {
    fn new() -> Self {
        Self {
            value: None,
            waker: None,
            closed: false,
        }
    }
}

#[cfg(feature = "kafka")]
#[derive(Debug)]
struct DeliverySender {
    inner: Arc<Mutex<DeliveryState>>,
}

#[cfg(feature = "kafka")]
impl DeliverySender {
    fn complete(self, value: Result<RecordMetadata, KafkaError>) {
        let mut state = self.inner.lock().expect("delivery lock poisoned");
        if state.closed || state.value.is_some() {
            return;
        }
        state.value = Some(value);
        if let Some(waker) = state.waker.take() {
            waker.wake();
        }
    }
}

#[cfg(feature = "kafka")]
#[derive(Debug)]
struct DeliveryReceiver {
    inner: Arc<Mutex<DeliveryState>>,
    cx: Cx,
}

#[cfg(feature = "kafka")]
impl Drop for DeliveryReceiver {
    fn drop(&mut self) {
        let mut state = self.inner.lock().expect("delivery lock poisoned");
        state.closed = true;
        state.waker = None;
    }
}

#[cfg(feature = "kafka")]
impl Future for DeliveryReceiver {
    type Output = Result<RecordMetadata, KafkaError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        if self.cx.checkpoint().is_err() {
            let mut state = self.inner.lock().expect("delivery lock poisoned");
            state.closed = true;
            state.waker = None;
            return Poll::Ready(Err(KafkaError::Cancelled));
        }

        let mut state = self.inner.lock().expect("delivery lock poisoned");
        if let Some(value) = state.value.take() {
            Poll::Ready(value)
        } else {
            state.waker = Some(cx.waker().clone());
            Poll::Pending
        }
    }
}

#[cfg(feature = "kafka")]
fn delivery_channel(cx: &Cx) -> (DeliverySender, DeliveryReceiver) {
    let inner = Arc::new(Mutex::new(DeliveryState::new()));
    (
        DeliverySender {
            inner: Arc::clone(&inner),
        },
        DeliveryReceiver {
            inner,
            cx: cx.clone(),
        },
    )
}

#[cfg(feature = "kafka")]
fn map_delivery_result(delivery_result: &DeliveryResult<'_>) -> Result<RecordMetadata, KafkaError> {
    match delivery_result {
        Ok(message) => Ok(record_metadata_from_message(message)),
        Err((err, message)) => Err(map_rdkafka_error(err, Some(message))),
    }
}

#[cfg(feature = "kafka")]
fn record_metadata_from_message(message: &BorrowedMessage<'_>) -> RecordMetadata {
    RecordMetadata {
        topic: message.topic().to_string(),
        partition: message.partition(),
        offset: message.offset(),
        timestamp: message.timestamp().to_millis(),
    }
}

#[cfg(feature = "kafka")]
fn map_rdkafka_error(err: &RdKafkaError, message: Option<&BorrowedMessage<'_>>) -> KafkaError {
    match err {
        RdKafkaError::ClientConfig(_, _, _, msg) => KafkaError::Config(msg.clone()),
        RdKafkaError::MessageProduction(code) => {
            map_error_code(*code, message.map(|msg| msg.topic()))
        }
        RdKafkaError::Canceled => KafkaError::Cancelled,
        _ => KafkaError::Broker(err.to_string()),
    }
}

#[cfg(feature = "kafka")]
fn map_error_code(code: RDKafkaErrorCode, topic: Option<&str>) -> KafkaError {
    match code {
        RDKafkaErrorCode::QueueFull => KafkaError::QueueFull,
        RDKafkaErrorCode::InvalidTopic | RDKafkaErrorCode::UnknownTopic => {
            KafkaError::InvalidTopic(topic.unwrap_or("unknown").to_string())
        }
        _ => KafkaError::Broker(format!("{code:?}")),
    }
}

#[cfg(feature = "kafka")]
fn compression_to_str(compression: Compression) -> &'static str {
    match compression {
        Compression::None => "none",
        Compression::Gzip => "gzip",
        Compression::Snappy => "snappy",
        Compression::Lz4 => "lz4",
        Compression::Zstd => "zstd",
    }
}

#[cfg(feature = "kafka")]
fn acks_to_str(acks: Acks) -> &'static str {
    match acks {
        Acks::None => "0",
        Acks::Leader => "1",
        Acks::All => "all",
    }
}

#[cfg(feature = "kafka")]
fn build_client_config(
    config: &ProducerConfig,
    transactional: Option<&TransactionalConfig>,
) -> Result<ClientConfig, KafkaError> {
    let mut client = ClientConfig::new();
    client.set("bootstrap.servers", config.bootstrap_servers.join(","));
    if let Some(client_id) = &config.client_id {
        client.set("client.id", client_id);
    }
    client.set("batch.size", config.batch_size.to_string());
    client.set("linger.ms", config.linger_ms.to_string());
    client.set("compression.type", compression_to_str(config.compression));
    client.set("enable.idempotence", config.enable_idempotence.to_string());
    client.set("acks", acks_to_str(config.acks));
    client.set("retries", config.retries.to_string());
    client.set(
        "request.timeout.ms",
        config.request_timeout.as_millis().to_string(),
    );
    client.set("message.max.bytes", config.max_message_size.to_string());

    if let Some(tx) = transactional {
        client.set("transactional.id", tx.transaction_id.as_str());
        client.set(
            "transaction.timeout.ms",
            tx.transaction_timeout.as_millis().to_string(),
        );
        client.set("enable.idempotence", "true");
    }

    Ok(client)
}

#[cfg(feature = "kafka")]
fn build_producer(
    config: &ProducerConfig,
    transactional: Option<&TransactionalConfig>,
) -> Result<ThreadedProducer<KafkaContext>, KafkaError> {
    let client = build_client_config(config, transactional)?;
    client
        .create_with_context(KafkaContext)
        .map_err(|err| map_rdkafka_error(&err, None))
}

#[cfg(feature = "kafka")]
async fn send_with_producer(
    producer: &ThreadedProducer<KafkaContext>,
    cx: &Cx,
    config: &ProducerConfig,
    topic: &str,
    key: Option<&[u8]>,
    payload: &[u8],
    partition: Option<i32>,
    headers: Option<&[(&str, &[u8])]>,
) -> Result<RecordMetadata, KafkaError> {
    cx.checkpoint().map_err(|_| KafkaError::Cancelled)?;

    if payload.len() > config.max_message_size {
        return Err(KafkaError::MessageTooLarge {
            size: payload.len(),
            max_size: config.max_message_size,
        });
    }

    let (sender, receiver) = delivery_channel(cx);

    let mut record = BaseRecord::with_opaque_to(topic, Box::new(sender)).payload(payload);
    if let Some(key) = key {
        record = record.key(key);
    }
    if let Some(partition) = partition {
        record = record.partition(partition);
    }
    if let Some(headers) = headers {
        let mut owned_headers = OwnedHeaders::new();
        for (key, value) in headers {
            owned_headers = owned_headers.insert(Header {
                key,
                value: Some(*value),
            });
        }
        record = record.headers(owned_headers);
    }

    match producer.send(record) {
        Ok(()) => receiver.await,
        Err((err, _)) => Err(map_rdkafka_error(&err, None)),
    }
}

/// Compression algorithm for Kafka messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Compression {
    /// No compression.
    #[default]
    None,
    /// Gzip compression.
    Gzip,
    /// Snappy compression.
    Snappy,
    /// LZ4 compression.
    Lz4,
    /// Zstandard compression.
    Zstd,
}

/// Acknowledgment level for producer requests.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Acks {
    /// No acknowledgment (fire and forget).
    None,
    /// Wait for leader acknowledgment.
    Leader,
    /// Wait for all in-sync replicas.
    #[default]
    All,
}

impl Acks {
    /// Convert to Kafka protocol value.
    #[must_use]
    pub const fn as_i16(&self) -> i16 {
        match self {
            Self::None => 0,
            Self::Leader => 1,
            Self::All => -1,
        }
    }
}

/// Configuration for Kafka producer.
#[derive(Debug, Clone)]
pub struct ProducerConfig {
    /// Bootstrap server addresses (host:port).
    pub bootstrap_servers: Vec<String>,
    /// Client identifier.
    pub client_id: Option<String>,
    /// Batch size in bytes (default: 16KB).
    pub batch_size: usize,
    /// Linger time before sending batch (default: 5ms).
    pub linger_ms: u64,
    /// Compression algorithm.
    pub compression: Compression,
    /// Enable idempotent producer (exactly-once without transactions).
    pub enable_idempotence: bool,
    /// Acknowledgment level.
    pub acks: Acks,
    /// Maximum retries for transient failures.
    pub retries: u32,
    /// Request timeout.
    pub request_timeout: Duration,
    /// Maximum message size in bytes.
    pub max_message_size: usize,
}

impl Default for ProducerConfig {
    fn default() -> Self {
        Self {
            bootstrap_servers: vec!["localhost:9092".to_string()],
            client_id: None,
            batch_size: 16_384, // 16KB
            linger_ms: 5,       // 5ms
            compression: Compression::None,
            enable_idempotence: true,
            acks: Acks::All,
            retries: 3,
            request_timeout: Duration::from_secs(30),
            max_message_size: 1_048_576, // 1MB
        }
    }
}

impl ProducerConfig {
    /// Create a new producer configuration.
    #[must_use]
    pub fn new(bootstrap_servers: Vec<String>) -> Self {
        Self {
            bootstrap_servers,
            ..Default::default()
        }
    }

    /// Set the client identifier.
    #[must_use]
    pub fn client_id(mut self, client_id: &str) -> Self {
        self.client_id = Some(client_id.to_string());
        self
    }

    /// Set the batch size in bytes.
    #[must_use]
    pub const fn batch_size(mut self, size: usize) -> Self {
        self.batch_size = size;
        self
    }

    /// Set the linger time in milliseconds.
    #[must_use]
    pub const fn linger_ms(mut self, ms: u64) -> Self {
        self.linger_ms = ms;
        self
    }

    /// Set the compression algorithm.
    #[must_use]
    pub const fn compression(mut self, compression: Compression) -> Self {
        self.compression = compression;
        self
    }

    /// Enable or disable idempotent producer.
    #[must_use]
    pub const fn enable_idempotence(mut self, enable: bool) -> Self {
        self.enable_idempotence = enable;
        self
    }

    /// Set the acknowledgment level.
    #[must_use]
    pub const fn acks(mut self, acks: Acks) -> Self {
        self.acks = acks;
        self
    }

    /// Set the maximum number of retries.
    #[must_use]
    pub const fn retries(mut self, retries: u32) -> Self {
        self.retries = retries;
        self
    }

    /// Validate the configuration.
    pub fn validate(&self) -> Result<(), KafkaError> {
        if self.bootstrap_servers.is_empty() {
            return Err(KafkaError::Config(
                "bootstrap_servers cannot be empty".to_string(),
            ));
        }
        if self.batch_size == 0 {
            return Err(KafkaError::Config("batch_size must be > 0".to_string()));
        }
        if self.max_message_size == 0 {
            return Err(KafkaError::Config(
                "max_message_size must be > 0".to_string(),
            ));
        }
        Ok(())
    }
}

/// Metadata returned after successfully sending a message.
#[derive(Debug, Clone)]
pub struct RecordMetadata {
    /// Topic the message was sent to.
    pub topic: String,
    /// Partition the message was written to.
    pub partition: i32,
    /// Offset within the partition.
    pub offset: i64,
    /// Timestamp of the message (milliseconds since epoch).
    pub timestamp: Option<i64>,
}

/// Kafka producer (Phase 0 stub).
///
/// Provides the API shape for a Kafka producer with Cx integration.
/// Full implementation requires rdkafka integration.
#[derive(Debug)]
pub struct KafkaProducer {
    config: ProducerConfig,
}

impl KafkaProducer {
    /// Create a new Kafka producer.
    pub fn new(config: ProducerConfig) -> Result<Self, KafkaError> {
        config.validate()?;
        Ok(Self { config })
    }

    /// Send a message to a topic.
    ///
    /// # Arguments
    /// * `cx` - Cancellation context
    /// * `topic` - Target topic name
    /// * `key` - Optional message key for partitioning
    /// * `payload` - Message payload
    /// * `partition` - Optional partition override
    ///
    /// # Errors
    /// Returns an error if the message cannot be sent.
    #[allow(unused_variables)]
    pub async fn send(
        &self,
        cx: &Cx,
        topic: &str,
        key: Option<&[u8]>,
        payload: &[u8],
        partition: Option<i32>,
    ) -> Result<RecordMetadata, KafkaError> {
        cx.checkpoint().map_err(|_| KafkaError::Cancelled)?;

        // Check message size
        if payload.len() > self.config.max_message_size {
            return Err(KafkaError::MessageTooLarge {
                size: payload.len(),
                max_size: self.config.max_message_size,
            });
        }

        // Phase 0: stub implementation
        Err(KafkaError::Io(io::Error::other(
            "Phase 0: requires rdkafka integration",
        )))
    }

    /// Send a message with headers.
    ///
    /// # Arguments
    /// * `cx` - Cancellation context
    /// * `topic` - Target topic name
    /// * `key` - Optional message key for partitioning
    /// * `payload` - Message payload
    /// * `headers` - Key-value header pairs
    #[allow(unused_variables)]
    pub async fn send_with_headers(
        &self,
        cx: &Cx,
        topic: &str,
        key: Option<&[u8]>,
        payload: &[u8],
        headers: &[(&str, &[u8])],
    ) -> Result<RecordMetadata, KafkaError> {
        cx.checkpoint().map_err(|_| KafkaError::Cancelled)?;

        if payload.len() > self.config.max_message_size {
            return Err(KafkaError::MessageTooLarge {
                size: payload.len(),
                max_size: self.config.max_message_size,
            });
        }

        Err(KafkaError::Io(io::Error::other(
            "Phase 0: requires rdkafka integration",
        )))
    }

    /// Flush all pending messages.
    ///
    /// Blocks until all messages in the queue are sent or the timeout expires.
    #[allow(unused_variables)]
    pub async fn flush(&self, cx: &Cx, timeout: Duration) -> Result<(), KafkaError> {
        cx.checkpoint().map_err(|_| KafkaError::Cancelled)?;

        Err(KafkaError::Io(io::Error::other(
            "Phase 0: requires rdkafka integration",
        )))
    }

    /// Get the current configuration.
    #[must_use]
    pub const fn config(&self) -> &ProducerConfig {
        &self.config
    }
}

/// Configuration for transactional producer.
#[derive(Debug, Clone)]
pub struct TransactionalConfig {
    /// Base producer configuration.
    pub producer: ProducerConfig,
    /// Transaction ID (must be unique per producer instance).
    pub transaction_id: String,
    /// Transaction timeout.
    pub transaction_timeout: Duration,
}

impl TransactionalConfig {
    /// Create a new transactional configuration.
    #[must_use]
    pub fn new(producer: ProducerConfig, transaction_id: String) -> Self {
        Self {
            producer,
            transaction_id,
            transaction_timeout: Duration::from_secs(60),
        }
    }

    /// Set the transaction timeout.
    #[must_use]
    pub const fn transaction_timeout(mut self, timeout: Duration) -> Self {
        self.transaction_timeout = timeout;
        self
    }
}

/// Transactional Kafka producer for exactly-once semantics.
///
/// Provides atomic message publishing across multiple topics/partitions.
#[derive(Debug)]
pub struct TransactionalProducer {
    config: TransactionalConfig,
}

impl TransactionalProducer {
    /// Create a new transactional producer.
    pub fn new(config: TransactionalConfig) -> Result<Self, KafkaError> {
        config.producer.validate()?;

        if config.transaction_id.is_empty() {
            return Err(KafkaError::Config(
                "transaction_id cannot be empty".to_string(),
            ));
        }

        Ok(Self { config })
    }

    /// Begin a new transaction.
    ///
    /// Returns a `Transaction` that must be committed or aborted.
    #[allow(unused_variables)]
    pub async fn begin_transaction(&self, cx: &Cx) -> Result<Transaction<'_>, KafkaError> {
        cx.checkpoint().map_err(|_| KafkaError::Cancelled)?;

        // Phase 0: stub implementation
        Err(KafkaError::Io(io::Error::other(
            "Phase 0: requires rdkafka integration",
        )))
    }

    /// Get the transaction ID.
    #[must_use]
    pub fn transaction_id(&self) -> &str {
        &self.config.transaction_id
    }

    /// Get the current configuration.
    #[must_use]
    pub const fn config(&self) -> &TransactionalConfig {
        &self.config
    }
}

/// An active Kafka transaction.
///
/// Messages sent within a transaction are atomically committed or aborted.
/// The transaction must be explicitly committed or aborted before being dropped.
#[derive(Debug)]
pub struct Transaction<'a> {
    producer: &'a TransactionalProducer,
    committed: bool,
}

impl Transaction<'_> {
    /// Send a message within the transaction.
    #[allow(unused_variables)]
    pub async fn send(
        &self,
        cx: &Cx,
        topic: &str,
        key: Option<&[u8]>,
        payload: &[u8],
    ) -> Result<(), KafkaError> {
        cx.checkpoint().map_err(|_| KafkaError::Cancelled)?;

        Err(KafkaError::Io(io::Error::other(
            "Phase 0: requires rdkafka integration",
        )))
    }

    /// Commit the transaction.
    ///
    /// Atomically publishes all messages sent within this transaction.
    #[allow(unused_variables)]
    pub async fn commit(mut self, cx: &Cx) -> Result<(), KafkaError> {
        cx.checkpoint().map_err(|_| KafkaError::Cancelled)?;

        // Phase 0: stub - mark as committed to prevent drop warning
        self.committed = true;

        Err(KafkaError::Io(io::Error::other(
            "Phase 0: requires rdkafka integration",
        )))
    }

    /// Abort the transaction.
    ///
    /// Discards all messages sent within this transaction.
    #[allow(unused_variables)]
    pub async fn abort(mut self, cx: &Cx) -> Result<(), KafkaError> {
        cx.checkpoint().map_err(|_| KafkaError::Cancelled)?;

        // Phase 0: stub - mark as committed to prevent drop warning
        self.committed = true;

        Err(KafkaError::Io(io::Error::other(
            "Phase 0: requires rdkafka integration",
        )))
    }
}

impl Drop for Transaction<'_> {
    fn drop(&mut self) {
        if !self.committed {
            // In production, this should log a warning about uncommitted transaction
            // The broker will abort it after transaction.timeout.ms expires
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_acks_values() {
        assert_eq!(Acks::None.as_i16(), 0);
        assert_eq!(Acks::Leader.as_i16(), 1);
        assert_eq!(Acks::All.as_i16(), -1);
    }

    #[test]
    fn test_config_defaults() {
        let config = ProducerConfig::default();
        assert_eq!(config.batch_size, 16_384);
        assert_eq!(config.linger_ms, 5);
        assert!(config.enable_idempotence);
        assert_eq!(config.acks, Acks::All);
    }

    #[test]
    fn test_config_builder() {
        let config = ProducerConfig::new(vec!["kafka:9092".to_string()])
            .client_id("my-producer")
            .batch_size(32_768)
            .compression(Compression::Snappy)
            .acks(Acks::Leader);

        assert_eq!(config.bootstrap_servers, vec!["kafka:9092"]);
        assert_eq!(config.client_id, Some("my-producer".to_string()));
        assert_eq!(config.batch_size, 32_768);
        assert_eq!(config.compression, Compression::Snappy);
        assert_eq!(config.acks, Acks::Leader);
    }

    #[test]
    fn test_config_validation() {
        let empty_servers = ProducerConfig {
            bootstrap_servers: vec![],
            ..Default::default()
        };
        assert!(empty_servers.validate().is_err());

        let valid = ProducerConfig::default();
        assert!(valid.validate().is_ok());
    }

    #[test]
    fn test_producer_creation() {
        let config = ProducerConfig::default();
        let producer = KafkaProducer::new(config);
        assert!(producer.is_ok());
    }

    #[test]
    fn test_transactional_config() {
        let config =
            TransactionalConfig::new(ProducerConfig::default(), "my-transaction-id".to_string())
                .transaction_timeout(Duration::from_secs(120));

        assert_eq!(config.transaction_id, "my-transaction-id");
        assert_eq!(config.transaction_timeout, Duration::from_secs(120));
    }

    #[test]
    fn test_transactional_producer_empty_id() {
        let config = TransactionalConfig::new(ProducerConfig::default(), String::new());
        let producer = TransactionalProducer::new(config);
        assert!(producer.is_err());
    }

    #[test]
    fn test_error_display() {
        let io_err = KafkaError::Io(io::Error::other("test"));
        assert!(io_err.to_string().contains("I/O error"));

        let msg_err = KafkaError::MessageTooLarge {
            size: 2_000_000,
            max_size: 1_000_000,
        };
        assert!(msg_err.to_string().contains("2000000"));
        assert!(msg_err.to_string().contains("1000000"));

        let cancelled = KafkaError::Cancelled;
        assert!(cancelled.to_string().contains("cancelled"));
    }

    #[test]
    fn test_record_metadata() {
        let meta = RecordMetadata {
            topic: "test-topic".to_string(),
            partition: 0,
            offset: 42,
            timestamp: Some(1_234_567_890),
        };
        assert_eq!(meta.topic, "test-topic");
        assert_eq!(meta.partition, 0);
        assert_eq!(meta.offset, 42);
        assert_eq!(meta.timestamp, Some(1_234_567_890));
    }
}
