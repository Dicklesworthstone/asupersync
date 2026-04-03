//! Kafka producer with Cx integration for cancel-correct message publishing.
//!
//! This module provides a Kafka producer with exactly-once semantics and
//! transactional support, integrated with the Asupersync `Cx` context for
//! proper cancellation handling.
//!
//! # Design
//!
//! The implementation wraps the rdkafka crate (when available) with a Cx
//! integration layer. When the `kafka` feature is disabled, the producer and
//! transaction APIs remain available only as a harness lane: sends land in a
//! deterministic in-process broker and transactions stage/commit/abort locally
//! so tests and contract probes can exercise honest semantics without implying
//! a real broker-backed deployment.
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

use crate::cx::Cx;
#[cfg(not(feature = "kafka"))]
use crate::sync::Notify;
use parking_lot::Mutex;
#[cfg(feature = "kafka")]
use rdkafka::producer::Producer;
#[cfg(not(feature = "kafka"))]
use std::collections::BTreeMap;
use std::fmt;
use std::io;
#[cfg(not(feature = "kafka"))]
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

#[cfg(feature = "kafka")]
use rdkafka::{
    client::ClientContext,
    config::ClientConfig,
    error::{KafkaError as RdKafkaError, RDKafkaErrorCode},
    message::{BorrowedMessage, DeliveryResult, Header, Message, OwnedHeaders},
    producer::{BaseRecord, ProducerContext, ThreadedProducer},
};
#[cfg(feature = "kafka")]
use std::future::Future;
#[cfg(feature = "kafka")]
use std::pin::Pin;
#[cfg(feature = "kafka")]
use std::sync::Arc;
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
    /// The future was polled after it had already completed.
    PolledAfterCompletion,
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
            Self::PolledAfterCompletion => {
                write!(f, "Kafka future polled after completion")
            }
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

impl KafkaError {
    /// Whether this error is transient and may succeed on retry.
    #[must_use]
    pub fn is_transient(&self) -> bool {
        matches!(
            self,
            Self::Io(_) | Self::Broker(_) | Self::QueueFull | Self::Transaction(_)
        )
    }

    /// Whether this error indicates a connection-level failure.
    #[must_use]
    pub fn is_connection_error(&self) -> bool {
        matches!(self, Self::Io(_) | Self::Broker(_))
    }

    /// Whether this error indicates resource/capacity exhaustion.
    #[must_use]
    pub fn is_capacity_error(&self) -> bool {
        matches!(self, Self::QueueFull | Self::MessageTooLarge { .. })
    }

    /// Whether this error is a timeout.
    #[must_use]
    pub fn is_timeout(&self) -> bool {
        matches!(self, Self::Io(e) if e.kind() == io::ErrorKind::TimedOut)
    }

    /// Whether the operation should be retried.
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        matches!(self, Self::Io(_) | Self::Broker(_) | Self::QueueFull)
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
    completed: bool,
}

#[cfg(feature = "kafka")]
impl DeliveryState {
    fn new() -> Self {
        Self {
            value: None,
            waker: None,
            closed: false,
            completed: false,
        }
    }
}

#[cfg(feature = "kafka")]
#[derive(Debug)]
struct DeliverySender {
    inner: Arc<Mutex<DeliveryState>>,
}

#[cfg(feature = "kafka")]
impl Drop for DeliverySender {
    fn drop(&mut self) {
        let waker = {
            let mut state = self.inner.lock();
            if state.closed || state.value.is_some() {
                return;
            }
            state.value = Some(Err(KafkaError::Cancelled));
            state.closed = true;
            state.waker.take()
        };
        if let Some(waker) = waker {
            waker.wake();
        }
    }
}

#[cfg(feature = "kafka")]
impl DeliverySender {
    fn complete(self, value: Result<RecordMetadata, KafkaError>) {
        let waker = {
            let mut state = self.inner.lock();
            if state.closed || state.value.is_some() {
                return;
            }
            state.value = Some(value);
            state.waker.take()
        };
        if let Some(waker) = waker {
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
        let mut state = self.inner.lock();
        state.closed = true;
        state.waker = None;
    }
}

#[cfg(feature = "kafka")]
impl Future for DeliveryReceiver {
    type Output = Result<RecordMetadata, KafkaError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut state = self.inner.lock();

        if state.completed {
            return Poll::Ready(Err(KafkaError::PolledAfterCompletion));
        }

        if self.cx.checkpoint().is_err() {
            state.closed = true;
            state.completed = true;
            state.waker = None;
            return Poll::Ready(Err(KafkaError::Cancelled));
        }

        if let Some(value) = state.value.take() {
            state.closed = true;
            state.completed = true;
            state.waker = None;
            Poll::Ready(value)
        } else {
            if !state
                .waker
                .as_ref()
                .is_some_and(|w| w.will_wake(cx.waker()))
            {
                state.waker = Some(cx.waker().clone());
            }
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
            map_error_code(*code, message.map(rdkafka::Message::topic))
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
struct SendRequest<'a> {
    topic: &'a str,
    key: Option<&'a [u8]>,
    payload: &'a [u8],
    partition: Option<i32>,
    headers: Option<&'a [(&'a str, &'a [u8])]>,
}

#[cfg(feature = "kafka")]
fn build_client_config(
    config: &ProducerConfig,
    transactional: Option<&TransactionalConfig>,
) -> ClientConfig {
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

    client
}

#[cfg(feature = "kafka")]
fn build_producer(
    config: &ProducerConfig,
    transactional: Option<&TransactionalConfig>,
) -> Result<ThreadedProducer<KafkaContext>, KafkaError> {
    let client = build_client_config(config, transactional);
    client
        .create_with_context(KafkaContext)
        .map_err(|err| map_rdkafka_error(&err, None))
}

#[cfg(feature = "kafka")]
async fn run_kafka_blocking<F, T>(cx: &Cx, f: F) -> T
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    if let Some(pool) = cx.blocking_pool_handle() {
        return crate::runtime::spawn_blocking::spawn_blocking_on_pool(pool, f).await;
    }

    crate::runtime::spawn_blocking::spawn_blocking_on_thread(f).await
}

#[cfg(feature = "kafka")]
async fn run_kafka_transaction_op<F>(cx: &Cx, f: F) -> Result<(), KafkaError>
where
    F: FnOnce() -> Result<(), RdKafkaError> + Send + 'static,
{
    run_kafka_blocking(cx, move || f().map_err(|err| map_rdkafka_error(&err, None))).await
}

#[cfg(feature = "kafka")]
async fn send_with_producer(
    producer: &ThreadedProducer<KafkaContext>,
    cx: &Cx,
    config: &ProducerConfig,
    request: SendRequest<'_>,
) -> Result<RecordMetadata, KafkaError> {
    cx.checkpoint().map_err(|_| KafkaError::Cancelled)?;

    if request.payload.len() > config.max_message_size {
        return Err(KafkaError::MessageTooLarge {
            size: request.payload.len(),
            max_size: config.max_message_size,
        });
    }

    let (sender, receiver) = delivery_channel(cx);

    let mut record =
        BaseRecord::with_opaque_to(request.topic, Box::new(sender)).payload(request.payload);
    if let Some(key) = request.key {
        record = record.key(key);
    }
    if let Some(partition) = request.partition {
        record = record.partition(partition);
    }
    if let Some(headers) = request.headers {
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

#[cfg(not(feature = "kafka"))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StubBrokerRecord {
    pub topic: String,
    pub partition: i32,
    pub key: Option<Vec<u8>>,
    pub payload: Vec<u8>,
    pub timestamp: Option<i64>,
    pub headers: Vec<(String, Vec<u8>)>,
}

#[cfg(not(feature = "kafka"))]
#[derive(Debug, Default)]
struct StubBrokerState {
    partitions: BTreeMap<(String, i32), Vec<StubBrokerRecord>>,
}

#[cfg(not(feature = "kafka"))]
#[derive(Debug)]
/// Harness-only deterministic in-process broker shared by the fallback
/// producer and consumer paths when the real Kafka feature is disabled.
struct StubBroker {
    state: Mutex<StubBrokerState>,
    notify: Notify,
}

#[cfg(not(feature = "kafka"))]
impl Default for StubBroker {
    fn default() -> Self {
        Self {
            state: Mutex::new(StubBrokerState::default()),
            notify: Notify::new(),
        }
    }
}

#[cfg(not(feature = "kafka"))]
static STUB_BROKER: OnceLock<StubBroker> = OnceLock::new();

#[cfg(all(not(feature = "kafka"), test))]
static STUB_BROKER_TEST_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

#[cfg(not(feature = "kafka"))]
fn stub_broker() -> &'static StubBroker {
    STUB_BROKER.get_or_init(StubBroker::default)
}

#[cfg(not(feature = "kafka"))]
pub(crate) fn stub_broker_notify() -> &'static Notify {
    &stub_broker().notify
}

#[cfg(not(feature = "kafka"))]
pub(crate) fn stub_broker_end_offset(topic: &str, partition: i32) -> i64 {
    let state = stub_broker().state.lock();
    state
        .partitions
        .get(&(topic.to_string(), partition))
        .map_or(0, |partition_log| {
            i64::try_from(partition_log.len()).unwrap_or(i64::MAX)
        })
}

#[cfg(not(feature = "kafka"))]
pub(crate) fn stub_broker_fetch(
    topic: &str,
    partition: i32,
    offset: i64,
) -> Option<StubBrokerRecord> {
    if offset < 0 {
        return None;
    }

    let state = stub_broker().state.lock();
    state
        .partitions
        .get(&(topic.to_string(), partition))
        .and_then(|partition_log| {
            usize::try_from(offset)
                .ok()
                .and_then(|index| partition_log.get(index).cloned())
        })
}

#[cfg(not(feature = "kafka"))]
pub(crate) fn stub_broker_publish(record: StubBrokerRecord) -> RecordMetadata {
    let metadata = {
        let mut state = stub_broker().state.lock();
        let partition_log = state
            .partitions
            .entry((record.topic.clone(), record.partition))
            .or_default();
        let offset = i64::try_from(partition_log.len()).unwrap_or(i64::MAX);
        let metadata = RecordMetadata {
            topic: record.topic.clone(),
            partition: record.partition,
            offset,
            timestamp: record.timestamp,
        };
        partition_log.push(record);
        drop(state);
        metadata
    };

    stub_broker().notify.notify_waiters();
    metadata
}

#[cfg(all(not(feature = "kafka"), test))]
pub(crate) fn reset_stub_broker_for_tests() {
    if let Some(broker) = STUB_BROKER.get() {
        broker.state.lock().partitions.clear();
        broker.notify.notify_waiters();
    }
}

#[cfg(all(not(feature = "kafka"), test))]
#[allow(dead_code)] // Guard held for test serialization — not read, just held
pub(crate) struct StubBrokerTestGuard(parking_lot::MutexGuard<'static, ()>);

#[cfg(all(not(feature = "kafka"), test))]
impl Drop for StubBrokerTestGuard {
    fn drop(&mut self) {
        reset_stub_broker_for_tests();
    }
}

#[cfg(all(not(feature = "kafka"), test))]
pub(crate) fn lock_stub_broker_for_tests() -> StubBrokerTestGuard {
    let lock = STUB_BROKER_TEST_LOCK.get_or_init(|| Mutex::new(()));
    let guard = lock.lock();

    // The harness broker is global state shared across producer and consumer
    // unit tests, so keep one test in the lane at a time and reset state on
    // both entry and exit.
    reset_stub_broker_for_tests();

    StubBrokerTestGuard(guard)
}

fn validate_topic(topic: &str) -> Result<(), KafkaError> {
    let topic = topic.trim();
    if topic.is_empty() {
        return Err(KafkaError::InvalidTopic(topic.to_string()));
    }
    Ok(())
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

/// Tracks whether the producer is truly idle or still finalizing a broker-side
/// transaction outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum TransactionPhase {
    #[default]
    Idle,
    Active,
    #[allow(dead_code)]
    // Transaction lifecycle state machine — used by mark_transaction_finalizing
    Finalizing,
    NeedsAbortRecovery,
}

#[derive(Debug, Default)]
struct TransactionalProducerState {
    phase: TransactionPhase,
    #[cfg(feature = "kafka")]
    initialized: bool,
    #[cfg(not(feature = "kafka"))]
    staged_records: Vec<StubBrokerRecord>,
}

/// Kafka producer with Cx integration.
///
/// With the `kafka` feature enabled this wraps a real `rdkafka` producer.
/// Without it, the producer talks to the harness-only in-process broker used
/// for tests and contract validation; it is not a production Kafka transport.
pub struct KafkaProducer {
    config: ProducerConfig,
    closed: AtomicBool,
    #[cfg(feature = "kafka")]
    producer: ThreadedProducer<KafkaContext>,
}

impl fmt::Debug for KafkaProducer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KafkaProducer")
            .field("config", &self.config)
            .field("closed", &self.is_closed())
            .finish_non_exhaustive()
    }
}

impl KafkaProducer {
    /// Create a new Kafka producer.
    pub fn new(config: ProducerConfig) -> Result<Self, KafkaError> {
        config.validate()?;

        #[cfg(feature = "kafka")]
        let producer = build_producer(&config, None)?;

        Ok(Self {
            config,
            closed: AtomicBool::new(false),
            #[cfg(feature = "kafka")]
            producer,
        })
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
    #[allow(unused_variables, clippy::unused_async)]
    pub async fn send(
        &self,
        cx: &Cx,
        topic: &str,
        key: Option<&[u8]>,
        payload: &[u8],
        partition: Option<i32>,
    ) -> Result<RecordMetadata, KafkaError> {
        cx.checkpoint().map_err(|_| KafkaError::Cancelled)?;
        self.ensure_open()?;
        validate_topic(topic)?;

        // Check message size
        if payload.len() > self.config.max_message_size {
            return Err(KafkaError::MessageTooLarge {
                size: payload.len(),
                max_size: self.config.max_message_size,
            });
        }

        #[cfg(feature = "kafka")]
        {
            send_with_producer(
                &self.producer,
                cx,
                &self.config,
                SendRequest {
                    topic,
                    key,
                    payload,
                    partition,
                    headers: None,
                },
            )
            .await
        }

        #[cfg(not(feature = "kafka"))]
        {
            Ok(stub_broker_publish(StubBrokerRecord {
                topic: topic.to_string(),
                partition: partition.unwrap_or(0),
                key: key.map(std::borrow::ToOwned::to_owned),
                payload: payload.to_vec(),
                timestamp: None,
                headers: Vec::new(),
            }))
        }
    }

    /// Send a message with headers.
    ///
    /// # Arguments
    /// * `cx` - Cancellation context
    /// * `topic` - Target topic name
    /// * `key` - Optional message key for partitioning
    /// * `payload` - Message payload
    /// * `headers` - Key-value header pairs
    #[allow(unused_variables, clippy::unused_async)]
    pub async fn send_with_headers(
        &self,
        cx: &Cx,
        topic: &str,
        key: Option<&[u8]>,
        payload: &[u8],
        headers: &[(&str, &[u8])],
    ) -> Result<RecordMetadata, KafkaError> {
        cx.checkpoint().map_err(|_| KafkaError::Cancelled)?;
        self.ensure_open()?;
        validate_topic(topic)?;

        if payload.len() > self.config.max_message_size {
            return Err(KafkaError::MessageTooLarge {
                size: payload.len(),
                max_size: self.config.max_message_size,
            });
        }

        #[cfg(feature = "kafka")]
        {
            send_with_producer(
                &self.producer,
                cx,
                &self.config,
                SendRequest {
                    topic,
                    key,
                    payload,
                    partition: None,
                    headers: Some(headers),
                },
            )
            .await
        }

        #[cfg(not(feature = "kafka"))]
        {
            Ok(stub_broker_publish(StubBrokerRecord {
                topic: topic.to_string(),
                partition: 0,
                key: key.map(std::borrow::ToOwned::to_owned),
                payload: payload.to_vec(),
                timestamp: None,
                headers: headers
                    .iter()
                    .map(|(key, value)| ((*key).to_string(), (*value).to_vec()))
                    .collect(),
            }))
        }
    }

    /// Flush all pending messages.
    ///
    /// Blocks until all messages in the queue are sent or the timeout expires.
    #[allow(unused_variables, clippy::unused_async)]
    pub async fn flush(&self, cx: &Cx, timeout: Duration) -> Result<(), KafkaError> {
        self.flush_inner(cx, timeout, false).await
    }

    /// Flush pending messages and close producer for new sends.
    ///
    /// This method is idempotent; repeated calls after the first successful
    /// close return `Ok(())`. If the close operation is cancelled while flushing,
    /// subsequent calls will retry the flush.
    pub async fn close(&self, cx: &Cx, timeout: Duration) -> Result<(), KafkaError> {
        cx.checkpoint().map_err(|_| KafkaError::Cancelled)?;

        // Mark as closed to block new sends. We use swap to ensure it's
        // always closed before we start flushing.
        self.closed.store(true, Ordering::Release);

        // Always flush. If a previous close was cancelled, this ensures
        // the remaining messages are still flushed upon retry.
        self.flush_inner(cx, timeout, true).await?;
        Ok(())
    }

    /// Whether this producer has been closed.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }

    #[allow(unused_variables, clippy::unused_async)]
    async fn flush_inner(
        &self,
        cx: &Cx,
        timeout: Duration,
        allow_closed: bool,
    ) -> Result<(), KafkaError> {
        cx.checkpoint().map_err(|_| KafkaError::Cancelled)?;
        if !allow_closed {
            self.ensure_open()?;
        }

        #[cfg(feature = "kafka")]
        {
            let mut remaining = timeout;
            loop {
                cx.checkpoint().map_err(|_| KafkaError::Cancelled)?;
                if self.producer.in_flight_count() == 0 {
                    break;
                }
                let tick = remaining.min(Duration::from_millis(10));
                self.producer.poll(tick);
                if remaining <= tick {
                    return Err(KafkaError::Broker("flush timeout elapsed".to_string()));
                }
                remaining -= tick;
            }
            Ok(())
        }

        #[cfg(not(feature = "kafka"))]
        {
            let _ = timeout;
            Ok(())
        }
    }

    fn ensure_open(&self) -> Result<(), KafkaError> {
        if self.closed.load(Ordering::Acquire) {
            Err(KafkaError::Config("producer is closed".to_string()))
        } else {
            Ok(())
        }
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
            transaction_timeout: Duration::from_mins(1),
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
/// Provides atomic message publishing across multiple topics/partitions. The
/// `kafka` feature uses broker-backed Kafka transactions. Without that feature,
/// transactions only stage against the harness broker so commit/abort
/// semantics stay testable without implying broker-backed exactly-once
/// delivery.
pub struct TransactionalProducer {
    config: TransactionalConfig,
    state: Mutex<TransactionalProducerState>,
    #[cfg(feature = "kafka")]
    producer: ThreadedProducer<KafkaContext>,
}

impl fmt::Debug for TransactionalProducer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let state = self.state.lock();
        f.debug_struct("TransactionalProducer")
            .field("config", &self.config)
            .field("phase", &state.phase)
            .finish_non_exhaustive()
    }
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

        #[cfg(feature = "kafka")]
        let producer = build_producer(&config.producer, Some(&config))?;

        Ok(Self {
            config,
            state: Mutex::new(TransactionalProducerState::default()),
            #[cfg(feature = "kafka")]
            producer,
        })
    }

    /// Begin a new transaction.
    ///
    /// Returns a `Transaction` that must be committed or aborted.
    pub async fn begin_transaction(&self, cx: &Cx) -> Result<Transaction<'_>, KafkaError> {
        cx.checkpoint().map_err(|_| KafkaError::Cancelled)?;
        self.recover_abandoned_transaction(cx).await?;
        self.ensure_initialized(cx).await?;
        self.activate_transaction()?;

        #[cfg(feature = "kafka")]
        if let Err(err) = run_kafka_transaction_op(cx, {
            let producer = self.producer.clone();
            move || producer.begin_transaction()
        })
        .await
        {
            self.mark_transaction_idle();
            return Err(err);
        }

        Ok(Transaction {
            producer: self,
            finished: false,
        })
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

    fn activate_transaction(&self) -> Result<(), KafkaError> {
        let mut state = self.state.lock();
        match state.phase {
            TransactionPhase::Idle => {
                state.phase = TransactionPhase::Active;
                #[cfg(not(feature = "kafka"))]
                state.staged_records.clear();
                drop(state);
                Ok(())
            }
            TransactionPhase::Active => Err(KafkaError::Transaction(
                "transaction already active".to_string(),
            )),
            TransactionPhase::Finalizing => Err(KafkaError::Transaction(
                "transaction finalization in progress".to_string(),
            )),
            TransactionPhase::NeedsAbortRecovery => Err(KafkaError::Transaction(
                "previous transaction requires abort recovery".to_string(),
            )),
        }
    }

    fn ensure_active_transaction(&self) -> Result<(), KafkaError> {
        let state = self.state.lock();
        match state.phase {
            TransactionPhase::Active => Ok(()),
            TransactionPhase::Idle => {
                Err(KafkaError::Transaction("no active transaction".to_string()))
            }
            TransactionPhase::Finalizing => Err(KafkaError::Transaction(
                "transaction finalization in progress".to_string(),
            )),
            TransactionPhase::NeedsAbortRecovery => Err(KafkaError::Transaction(
                "transaction is poisoned and must be aborted before reuse".to_string(),
            )),
        }
    }

    #[allow(dead_code)] // Transaction lifecycle state machine
    fn mark_transaction_finalizing(&self) {
        let mut state = self.state.lock();
        if state.phase == TransactionPhase::Active {
            state.phase = TransactionPhase::Finalizing;
        }
    }

    fn mark_transaction_idle(&self) {
        let mut state = self.state.lock();
        state.phase = TransactionPhase::Idle;
        #[cfg(not(feature = "kafka"))]
        state.staged_records.clear();
    }

    #[allow(dead_code)] // Transaction lifecycle state machine
    fn mark_transaction_needs_abort(&self) {
        let mut state = self.state.lock();
        state.phase = TransactionPhase::NeedsAbortRecovery;
        #[cfg(not(feature = "kafka"))]
        state.staged_records.clear();
    }

    fn mark_transaction_dropped(&self) {
        let mut state = self.state.lock();
        if matches!(
            state.phase,
            TransactionPhase::Active | TransactionPhase::Finalizing
        ) {
            state.phase = TransactionPhase::NeedsAbortRecovery;
            #[cfg(not(feature = "kafka"))]
            state.staged_records.clear();
        }
    }

    #[cfg(feature = "kafka")]
    async fn ensure_initialized(&self, cx: &Cx) -> Result<(), KafkaError> {
        if self.state.lock().initialized {
            return Ok(());
        }

        run_kafka_transaction_op(cx, {
            let producer = self.producer.clone();
            let timeout = self.config.transaction_timeout;
            move || producer.init_transactions(timeout)
        })
        .await?;

        self.state.lock().initialized = true;
        Ok(())
    }

    #[cfg(not(feature = "kafka"))]
    #[allow(clippy::unused_async)]
    async fn ensure_initialized(&self, _cx: &Cx) -> Result<(), KafkaError> {
        Ok(())
    }

    #[allow(clippy::unused_async)]
    async fn recover_abandoned_transaction(&self, cx: &Cx) -> Result<(), KafkaError> {
        if self.state.lock().phase != TransactionPhase::NeedsAbortRecovery {
            return Ok(());
        }

        #[cfg(not(feature = "kafka"))]
        let _ = cx;

        #[cfg(feature = "kafka")]
        run_kafka_transaction_op(cx, {
            let producer = self.producer.clone();
            let timeout = self.config.transaction_timeout;
            move || producer.abort_transaction(timeout)
        })
        .await?;

        self.mark_transaction_idle();
        Ok(())
    }
}

/// An active Kafka transaction.
///
/// Messages sent within a transaction are atomically committed or aborted.
/// The transaction must be explicitly committed or aborted before being dropped.
#[derive(Debug)]
pub struct Transaction<'a> {
    producer: &'a TransactionalProducer,
    finished: bool,
}

impl Transaction<'_> {
    /// Send a message within the transaction.
    #[allow(unused_variables, clippy::unused_async)]
    pub async fn send(
        &self,
        cx: &Cx,
        topic: &str,
        key: Option<&[u8]>,
        payload: &[u8],
    ) -> Result<(), KafkaError> {
        cx.checkpoint().map_err(|_| KafkaError::Cancelled)?;
        self.producer.ensure_active_transaction()?;
        validate_topic(topic)?;

        if payload.len() > self.producer.config.producer.max_message_size {
            return Err(KafkaError::MessageTooLarge {
                size: payload.len(),
                max_size: self.producer.config.producer.max_message_size,
            });
        }

        #[cfg(feature = "kafka")]
        {
            send_with_producer(
                &self.producer.producer,
                cx,
                &self.producer.config.producer,
                SendRequest {
                    topic,
                    key,
                    payload,
                    partition: None,
                    headers: None,
                },
            )
            .await
            .map(|_metadata| ())
        }

        #[cfg(not(feature = "kafka"))]
        {
            let mut state = self.producer.state.lock();
            if state.phase != TransactionPhase::Active {
                return Err(KafkaError::Transaction(
                    "transaction is not available for sends".to_string(),
                ));
            }
            state.staged_records.push(StubBrokerRecord {
                topic: topic.to_string(),
                partition: 0,
                key: key.map(std::borrow::ToOwned::to_owned),
                payload: payload.to_vec(),
                timestamp: None,
                headers: Vec::new(),
            });
            drop(state);
            Ok(())
        }
    }

    /// Commit the transaction.
    ///
    /// Atomically publishes all messages sent within this transaction.
    #[allow(unused_variables, clippy::unused_async)]
    pub async fn commit(mut self, cx: &Cx) -> Result<(), KafkaError> {
        cx.checkpoint().map_err(|_| KafkaError::Cancelled)?;
        self.producer.ensure_active_transaction()?;

        #[cfg(feature = "kafka")]
        {
            self.producer.mark_transaction_finalizing();
            let result = run_kafka_transaction_op(cx, {
                let producer = self.producer.producer.clone();
                let timeout = self.producer.config.transaction_timeout;
                move || producer.commit_transaction(timeout)
            })
            .await;
            self.finished = true;
            if let Err(err) = result {
                self.producer.mark_transaction_needs_abort();
                return Err(err);
            }
            self.producer.mark_transaction_idle();
        }

        #[cfg(not(feature = "kafka"))]
        {
            let staged = {
                let mut state = self.producer.state.lock();
                if state.phase != TransactionPhase::Active {
                    return Err(KafkaError::Transaction(
                        "transaction is not active".to_string(),
                    ));
                }
                state.phase = TransactionPhase::Idle;
                std::mem::take(&mut state.staged_records)
            };

            for record in staged {
                let _ = stub_broker_publish(record);
            }
            self.finished = true;
        }

        Ok(())
    }

    /// Abort the transaction.
    ///
    /// Discards all messages sent within this transaction.
    #[allow(unused_variables, clippy::unused_async)]
    pub async fn abort(mut self, cx: &Cx) -> Result<(), KafkaError> {
        cx.checkpoint().map_err(|_| KafkaError::Cancelled)?;
        self.producer.ensure_active_transaction()?;

        #[cfg(feature = "kafka")]
        {
            self.producer.mark_transaction_finalizing();
            let result = run_kafka_transaction_op(cx, {
                let producer = self.producer.producer.clone();
                let timeout = self.producer.config.transaction_timeout;
                move || producer.abort_transaction(timeout)
            })
            .await;
            self.finished = true;
            if let Err(err) = result {
                self.producer.mark_transaction_needs_abort();
                return Err(err);
            }
            self.producer.mark_transaction_idle();
        }

        #[cfg(not(feature = "kafka"))]
        {
            self.producer.mark_transaction_idle();
            self.finished = true;
        }

        Ok(())
    }
}

impl Drop for Transaction<'_> {
    fn drop(&mut self) {
        if !self.finished {
            self.producer.mark_transaction_dropped();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "kafka")]
    use futures_lite::future;
    #[cfg(feature = "kafka")]
    use std::sync::Arc;
    #[cfg(feature = "kafka")]
    use std::task::{Context, Wake, Waker};

    #[cfg(not(feature = "kafka"))]
    fn stub_broker_guard() -> StubBrokerTestGuard {
        lock_stub_broker_for_tests()
    }

    #[cfg(feature = "kafka")]
    struct NoopWaker;

    #[cfg(feature = "kafka")]
    impl Wake for NoopWaker {
        fn wake(self: Arc<Self>) {}
    }

    #[cfg(feature = "kafka")]
    fn noop_waker() -> Waker {
        Waker::from(Arc::new(NoopWaker))
    }

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

        let done = KafkaError::PolledAfterCompletion;
        assert!(done.to_string().contains("polled after completion"));
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

    // Pure data-type tests (wave 13 – CyanBarn)

    #[test]
    fn kafka_error_display_all_variants() {
        assert!(
            KafkaError::Io(io::Error::other("e"))
                .to_string()
                .contains("I/O error")
        );
        assert!(
            KafkaError::Protocol("p".into())
                .to_string()
                .contains("protocol error")
        );
        assert!(
            KafkaError::Broker("b".into())
                .to_string()
                .contains("broker error")
        );
        assert!(KafkaError::QueueFull.to_string().contains("queue is full"));
        assert!(
            KafkaError::MessageTooLarge {
                size: 10,
                max_size: 5
            }
            .to_string()
            .contains("10")
        );
        assert!(
            KafkaError::InvalidTopic("bad".into())
                .to_string()
                .contains("bad")
        );
        assert!(
            KafkaError::Transaction("tx".into())
                .to_string()
                .contains("transaction error")
        );
        assert!(KafkaError::Cancelled.to_string().contains("cancelled"));
        assert!(
            KafkaError::PolledAfterCompletion
                .to_string()
                .contains("polled after completion")
        );
        assert!(
            KafkaError::Config("cfg".into())
                .to_string()
                .contains("configuration error")
        );
    }

    #[test]
    fn kafka_error_debug() {
        let err = KafkaError::QueueFull;
        let dbg = format!("{err:?}");
        assert!(dbg.contains("QueueFull"));
    }

    #[test]
    fn kafka_error_source_io() {
        let err = KafkaError::Io(io::Error::other("disk"));
        let src = std::error::Error::source(&err);
        assert!(src.is_some());
    }

    #[test]
    fn kafka_error_source_none_for_others() {
        let err = KafkaError::Cancelled;
        assert!(std::error::Error::source(&err).is_none());

        let done = KafkaError::PolledAfterCompletion;
        assert!(std::error::Error::source(&done).is_none());
    }

    #[test]
    fn kafka_error_from_io() {
        let io_err = io::Error::other("net");
        let err: KafkaError = KafkaError::from(io_err);
        assert!(matches!(err, KafkaError::Io(_)));
    }

    #[test]
    fn compression_default_is_none() {
        assert_eq!(Compression::default(), Compression::None);
    }

    #[test]
    fn compression_debug_clone_copy_eq() {
        let c = Compression::Snappy;
        let dbg = format!("{c:?}");
        assert!(dbg.contains("Snappy"));

        let copy = c;
        assert_eq!(c, copy);
    }

    #[test]
    fn compression_all_variants_ne() {
        let variants = [
            Compression::None,
            Compression::Gzip,
            Compression::Snappy,
            Compression::Lz4,
            Compression::Zstd,
        ];
        for (i, a) in variants.iter().enumerate() {
            for (j, b) in variants.iter().enumerate() {
                if i != j {
                    assert_ne!(a, b);
                }
            }
        }
    }

    #[test]
    fn acks_default_is_all() {
        assert_eq!(Acks::default(), Acks::All);
    }

    #[test]
    fn acks_debug_clone_copy_eq() {
        let a = Acks::Leader;
        let dbg = format!("{a:?}");
        assert!(dbg.contains("Leader"));

        let copy = a;
        assert_eq!(a, copy);
    }

    #[test]
    fn acks_as_i16_all_variants() {
        assert_eq!(Acks::None.as_i16(), 0);
        assert_eq!(Acks::Leader.as_i16(), 1);
        assert_eq!(Acks::All.as_i16(), -1);
    }

    #[test]
    fn producer_config_default_values() {
        let cfg = ProducerConfig::default();
        assert_eq!(cfg.bootstrap_servers, vec!["localhost:9092".to_string()]);
        assert!(cfg.client_id.is_none());
        assert_eq!(cfg.batch_size, 16_384);
        assert_eq!(cfg.linger_ms, 5);
        assert_eq!(cfg.compression, Compression::None);
        assert!(cfg.enable_idempotence);
        assert_eq!(cfg.acks, Acks::All);
        assert_eq!(cfg.retries, 3);
        assert_eq!(cfg.request_timeout, Duration::from_secs(30));
        assert_eq!(cfg.max_message_size, 1_048_576);
    }

    #[test]
    fn producer_config_debug_clone() {
        let cfg = ProducerConfig::default();
        let dbg = format!("{cfg:?}");
        assert!(dbg.contains("ProducerConfig"));

        let cloned = cfg;
        assert_eq!(cloned.batch_size, 16_384);
    }

    #[test]
    fn producer_config_builder_linger_retries() {
        let cfg = ProducerConfig::new(vec!["k:9092".into()])
            .linger_ms(100)
            .retries(10)
            .enable_idempotence(false);
        assert_eq!(cfg.linger_ms, 100);
        assert_eq!(cfg.retries, 10);
        assert!(!cfg.enable_idempotence);
    }

    #[test]
    fn producer_config_validate_zero_batch_size() {
        let cfg = ProducerConfig {
            batch_size: 0,
            ..Default::default()
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn producer_config_validate_zero_max_message() {
        let cfg = ProducerConfig {
            max_message_size: 0,
            ..Default::default()
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn record_metadata_debug_clone() {
        let meta = RecordMetadata {
            topic: "t".into(),
            partition: 1,
            offset: 99,
            timestamp: None,
        };
        let dbg = format!("{meta:?}");
        assert!(dbg.contains("RecordMetadata"));

        let cloned = meta;
        assert_eq!(cloned.partition, 1);
        assert!(cloned.timestamp.is_none());
    }

    #[test]
    fn kafka_producer_config_accessor() {
        let cfg = ProducerConfig::new(vec!["host:9092".into()]).batch_size(999);
        let producer = KafkaProducer::new(cfg).unwrap();
        assert_eq!(producer.config().batch_size, 999);
    }

    #[test]
    fn kafka_producer_debug() {
        let producer = KafkaProducer::new(ProducerConfig::default()).unwrap();
        let dbg = format!("{producer:?}");
        assert!(dbg.contains("KafkaProducer"));
    }

    #[test]
    fn kafka_producer_reject_empty_servers() {
        let cfg = ProducerConfig {
            bootstrap_servers: vec![],
            ..Default::default()
        };
        assert!(KafkaProducer::new(cfg).is_err());
    }

    #[test]
    fn transactional_config_debug_clone() {
        let tc = TransactionalConfig::new(ProducerConfig::default(), "tx-1".into());
        let dbg = format!("{tc:?}");
        assert!(dbg.contains("TransactionalConfig"));

        let cloned = tc;
        assert_eq!(cloned.transaction_id, "tx-1");
    }

    #[test]
    fn transactional_config_default_timeout() {
        let tc = TransactionalConfig::new(ProducerConfig::default(), "tx-2".into());
        assert_eq!(tc.transaction_timeout, Duration::from_mins(1));
    }

    #[test]
    fn transactional_producer_debug() {
        let tc = TransactionalConfig::new(ProducerConfig::default(), "tx-3".into());
        let producer = TransactionalProducer::new(tc).unwrap();
        let dbg = format!("{producer:?}");
        assert!(dbg.contains("TransactionalProducer"));
    }

    #[test]
    fn transactional_producer_accessors() {
        let tc = TransactionalConfig::new(ProducerConfig::default(), "tx-4".into());
        let producer = TransactionalProducer::new(tc).unwrap();
        assert_eq!(producer.transaction_id(), "tx-4");
        assert_eq!(producer.config().transaction_id, "tx-4");
    }

    #[test]
    fn transactional_producer_rejects_begin_while_finalizing() {
        let tc = TransactionalConfig::new(ProducerConfig::default(), "tx-finalizing-begin".into());
        let producer = TransactionalProducer::new(tc).unwrap();
        producer.state.lock().phase = TransactionPhase::Finalizing;

        let err = producer.activate_transaction().unwrap_err();
        assert!(
            matches!(err, KafkaError::Transaction(msg) if msg.contains("finalization in progress"))
        );
    }

    #[test]
    fn transactional_producer_rejects_send_checks_while_finalizing() {
        let tc = TransactionalConfig::new(ProducerConfig::default(), "tx-finalizing-send".into());
        let producer = TransactionalProducer::new(tc).unwrap();
        producer.state.lock().phase = TransactionPhase::Finalizing;

        let err = producer.ensure_active_transaction().unwrap_err();
        assert!(
            matches!(err, KafkaError::Transaction(msg) if msg.contains("finalization in progress"))
        );
    }

    #[test]
    fn transactional_producer_drop_poison_active_and_finalizing_phases() {
        let tc = TransactionalConfig::new(ProducerConfig::default(), "tx-drop-phases".into());
        let producer = TransactionalProducer::new(tc).unwrap();

        producer.state.lock().phase = TransactionPhase::Finalizing;
        producer.mark_transaction_dropped();
        assert_eq!(
            producer.state.lock().phase,
            TransactionPhase::NeedsAbortRecovery
        );

        producer.state.lock().phase = TransactionPhase::Active;
        producer.mark_transaction_dropped();
        assert_eq!(
            producer.state.lock().phase,
            TransactionPhase::NeedsAbortRecovery
        );
    }

    #[test]
    fn dropping_unfinished_transaction_in_finalizing_phase_requires_abort_recovery() {
        let tc = TransactionalConfig::new(ProducerConfig::default(), "tx-drop-finalizing".into());
        let producer = TransactionalProducer::new(tc).unwrap();
        producer.state.lock().phase = TransactionPhase::Finalizing;

        {
            let tx = Transaction {
                producer: &producer,
                finished: false,
            };
            drop(tx);
        }

        assert_eq!(
            producer.state.lock().phase,
            TransactionPhase::NeedsAbortRecovery
        );
    }

    #[cfg(not(feature = "kafka"))]
    #[test]
    fn transactional_fallback_commit_applies_staged_offsets_on_commit() {
        let _broker = stub_broker_guard();
        crate::test_utils::run_test_with_cx(|cx| async move {
            let topic = "transactional-fallback-commit-applies";
            let producer = TransactionalProducer::new(TransactionalConfig::new(
                ProducerConfig::default(),
                "tx-commit-applies".to_string(),
            ))
            .unwrap();

            let tx = producer.begin_transaction(&cx).await.unwrap();
            tx.send(&cx, topic, Some(b"k1"), b"one").await.unwrap();
            tx.send(&cx, topic, Some(b"k2"), b"two").await.unwrap();
            tx.commit(&cx).await.unwrap();

            let plain = KafkaProducer::new(ProducerConfig::default()).unwrap();
            let metadata = plain
                .send(&cx, topic, None, b"after", Some(0))
                .await
                .unwrap();
            assert_eq!(metadata.offset, 2);
        });
    }

    #[cfg(not(feature = "kafka"))]
    #[test]
    fn transactional_fallback_abort_discards_staged_offsets() {
        let _broker = stub_broker_guard();
        crate::test_utils::run_test_with_cx(|cx| async move {
            let topic = "transactional-fallback-abort-discards";
            let producer = TransactionalProducer::new(TransactionalConfig::new(
                ProducerConfig::default(),
                "tx-abort-discards".to_string(),
            ))
            .unwrap();

            let tx = producer.begin_transaction(&cx).await.unwrap();
            tx.send(&cx, topic, None, b"one").await.unwrap();
            tx.send(&cx, topic, None, b"two").await.unwrap();
            tx.abort(&cx).await.unwrap();

            let plain = KafkaProducer::new(ProducerConfig::default()).unwrap();
            let metadata = plain
                .send(&cx, topic, None, b"after", Some(0))
                .await
                .unwrap();
            assert_eq!(metadata.offset, 0);
        });
    }

    #[cfg(not(feature = "kafka"))]
    #[test]
    fn transactional_fallback_rejects_concurrent_begin() {
        let _broker = stub_broker_guard();
        crate::test_utils::run_test_with_cx(|cx| async move {
            let producer = TransactionalProducer::new(TransactionalConfig::new(
                ProducerConfig::default(),
                "tx-active-check".to_string(),
            ))
            .unwrap();

            let tx = producer.begin_transaction(&cx).await.unwrap();
            let err = producer.begin_transaction(&cx).await.unwrap_err();
            assert!(matches!(err, KafkaError::Transaction(msg) if msg.contains("already active")));
            tx.abort(&cx).await.unwrap();
        });
    }

    #[cfg(not(feature = "kafka"))]
    #[test]
    fn transactional_fallback_drop_requires_recovery_before_next_begin() {
        let _broker = stub_broker_guard();
        crate::test_utils::run_test_with_cx(|cx| async move {
            let topic = "transactional-fallback-drop-recovery";
            let producer = TransactionalProducer::new(TransactionalConfig::new(
                ProducerConfig::default(),
                "tx-drop-recovery".to_string(),
            ))
            .unwrap();

            let tx = producer.begin_transaction(&cx).await.unwrap();
            tx.send(&cx, topic, None, b"staged-then-dropped")
                .await
                .unwrap();
            drop(tx);

            let next = producer.begin_transaction(&cx).await.unwrap();
            next.send(&cx, topic, None, b"committed").await.unwrap();
            next.commit(&cx).await.unwrap();

            let plain = KafkaProducer::new(ProducerConfig::default()).unwrap();
            let metadata = plain
                .send(&cx, topic, None, b"after", Some(0))
                .await
                .unwrap();
            assert_eq!(metadata.offset, 1);
        });
    }

    #[test]
    fn compression_debug_clone_copy_default_eq() {
        let c = Compression::default();
        assert_eq!(c, Compression::None);
        let dbg = format!("{c:?}");
        assert!(dbg.contains("None"), "{dbg}");
        let copied: Compression = c;
        let cloned = c;
        assert_eq!(copied, cloned);
        assert_ne!(c, Compression::Zstd);
    }

    #[test]
    fn acks_debug_clone_copy_default_eq() {
        let a = Acks::default();
        assert_eq!(a, Acks::All);
        let dbg = format!("{a:?}");
        assert!(dbg.contains("All"), "{dbg}");
        let copied: Acks = a;
        let cloned = a;
        assert_eq!(copied, cloned);
        assert_ne!(a, Acks::Leader);
    }

    #[cfg(not(feature = "kafka"))]
    #[test]
    fn producer_send_returns_deterministic_delivery_metadata() {
        let _broker = stub_broker_guard();
        crate::test_utils::run_test_with_cx(|cx| async move {
            let producer = KafkaProducer::new(ProducerConfig::default()).unwrap();

            // Use unique topic name to avoid cross-test contamination via the
            // global STUB_DELIVERY_OFFSETS static.
            let topic = "deterministic-delivery-metadata-test";
            let first = producer
                .send(&cx, topic, None, b"first", Some(2))
                .await
                .unwrap();
            let second = producer
                .send_with_headers(
                    &cx,
                    topic,
                    Some(b"key"),
                    b"second",
                    &[("trace-id", b"abc-123")],
                )
                .await
                .unwrap();

            assert_eq!(first.topic, topic);
            assert_eq!(first.partition, 2);
            assert_eq!(first.offset, 0);
            assert_eq!(second.partition, 0);
            assert_eq!(second.offset, 0);

            let third = producer
                .send(&cx, topic, None, b"third", Some(2))
                .await
                .unwrap();
            assert_eq!(third.offset, first.offset + 1);

            producer.flush(&cx, Duration::from_millis(5)).await.unwrap();
        });
    }

    #[cfg(not(feature = "kafka"))]
    #[test]
    fn producer_rejects_blank_topic_name() {
        let _broker = stub_broker_guard();
        crate::test_utils::run_test_with_cx(|cx| async move {
            let producer = KafkaProducer::new(ProducerConfig::default()).unwrap();
            let err = producer
                .send(&cx, "   ", None, b"x", None)
                .await
                .unwrap_err();
            assert!(matches!(err, KafkaError::InvalidTopic(topic) if topic.is_empty()));
        });
    }

    #[cfg(not(feature = "kafka"))]
    #[test]
    fn producer_close_is_idempotent_and_blocks_new_operations() {
        let _broker = stub_broker_guard();
        crate::test_utils::run_test_with_cx(|cx| async move {
            let producer = KafkaProducer::new(ProducerConfig::default()).unwrap();
            producer
                .send(&cx, "orders", None, b"before-close", None)
                .await
                .unwrap();

            producer.close(&cx, Duration::from_millis(5)).await.unwrap();
            producer.close(&cx, Duration::from_millis(5)).await.unwrap();
            assert!(producer.is_closed());

            let send_err = producer
                .send(&cx, "orders", None, b"after-close", None)
                .await
                .unwrap_err();
            assert!(matches!(send_err, KafkaError::Config(msg) if msg.contains("closed")));

            let flush_err = producer
                .flush(&cx, Duration::from_millis(1))
                .await
                .unwrap_err();
            assert!(matches!(flush_err, KafkaError::Config(msg) if msg.contains("closed")));
        });
    }

    #[cfg(feature = "kafka")]
    #[test]
    fn delivery_receiver_repoll_after_success_fails_closed() {
        let cx = Cx::for_testing();
        let (sender, receiver) = delivery_channel(&cx);
        sender.complete(Ok(RecordMetadata {
            topic: "orders".to_string(),
            partition: 2,
            offset: 41,
            timestamp: Some(123),
        }));

        let waker = noop_waker();
        let mut task_cx = Context::from_waker(&waker);
        let mut receiver = std::pin::pin!(receiver);

        match receiver.as_mut().poll(&mut task_cx) {
            Poll::Ready(Ok(metadata)) => {
                assert_eq!(metadata.topic, "orders");
                assert_eq!(metadata.partition, 2);
                assert_eq!(metadata.offset, 41);
                assert_eq!(metadata.timestamp, Some(123));
            }
            other => panic!("expected Ready(Ok(_)), got {other:?}"),
        }

        assert!(matches!(
            receiver.as_mut().poll(&mut task_cx),
            Poll::Ready(Err(KafkaError::PolledAfterCompletion))
        ));
    }

    #[cfg(feature = "kafka")]
    #[test]
    fn delivery_receiver_repoll_after_cancellation_fails_closed() {
        let cx = Cx::for_testing();
        cx.set_cancel_requested(true);
        let (_sender, receiver) = delivery_channel(&cx);

        let waker = noop_waker();
        let mut task_cx = Context::from_waker(&waker);
        let mut receiver = std::pin::pin!(receiver);

        assert!(matches!(
            receiver.as_mut().poll(&mut task_cx),
            Poll::Ready(Err(KafkaError::Cancelled))
        ));
        assert!(matches!(
            receiver.as_mut().poll(&mut task_cx),
            Poll::Ready(Err(KafkaError::PolledAfterCompletion))
        ));
    }

    #[cfg(feature = "kafka")]
    #[test]
    fn run_kafka_blocking_uses_pool_when_available() {
        let pool = crate::runtime::BlockingPool::new(1, 1);
        let cx = Cx::for_testing().with_blocking_pool_handle(Some(pool.handle()));

        let thread_name = future::block_on(async {
            run_kafka_blocking(&cx, || {
                std::thread::current()
                    .name()
                    .unwrap_or("unnamed")
                    .to_string()
            })
            .await
        });

        assert!(
            thread_name.contains("-blocking-"),
            "expected pool-backed kafka blocking work to run on a blocking-pool thread, got {thread_name}"
        );
    }

    #[cfg(feature = "kafka")]
    #[test]
    fn run_kafka_blocking_offloads_even_without_pool() {
        let cx = Cx::for_testing();
        let current_id = std::thread::current().id();

        let (thread_id, thread_name) = future::block_on(async {
            run_kafka_blocking(&cx, || {
                (
                    std::thread::current().id(),
                    std::thread::current()
                        .name()
                        .unwrap_or("unnamed")
                        .to_string(),
                )
            })
            .await
        });

        assert_ne!(
            thread_id, current_id,
            "kafka blocking helper should use a dedicated thread even when the runtime has no blocking pool"
        );
        assert_eq!(
            thread_name, "asupersync-blocking",
            "expected kafka blocking helper to use the dedicated blocking-thread fallback"
        );
    }
}
