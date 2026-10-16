//! Kafka producer with Cx integration for cancel-correct message publishing.
//!
//! This module provides a Kafka producer with exactly-once semantics and
//! transactional support, integrated with the Asupersync `Cx` context for
//! proper cancellation handling.
//!
//! # Design
//!
//! The implementation wraps the rdkafka crate (when available) with a Cx
//! integration layer. When the `kafka` feature is disabled, broker operations
//! fail closed with [`KafkaError::FeatureDisabled`] outside crate unit tests.
//! Unit tests keep a cfg-gated deterministic in-process broker so the producer
//! and transaction state machines remain covered without shipping broker
//! surrogate behavior to downstream builds.
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
use crate::messaging::kafka_consumer::{
    ConsumerGroupMetadata, PreparedTransactionOffsets, TopicPartitionOffset,
};
use crate::sync::Notify;
use parking_lot::Mutex;
#[cfg(feature = "kafka")]
use rdkafka::producer::Producer;
#[cfg(all(not(feature = "kafka"), any(test, feature = "test-internals")))]
use std::collections::BTreeMap;
use std::fmt;
use std::io;
#[cfg(all(not(feature = "kafka"), any(test, feature = "test-internals")))]
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;
use zeroize::ZeroizeOnDrop;

#[cfg(feature = "kafka")]
use rdkafka::{
    client::ClientContext,
    config::ClientConfig,
    consumer::{BaseConsumer, Consumer, ConsumerContext},
    error::{KafkaError as RdKafkaError, RDKafkaErrorCode},
    message::{BorrowedMessage, DeliveryResult, Header, Message, OwnedHeaders},
    producer::{BaseRecord, ProducerContext, ThreadedProducer},
};
#[cfg(feature = "kafka")]
use std::future::Future;
#[cfg(feature = "kafka")]
use std::pin::Pin;
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
    /// Authentication failure (credentials rejected or SASL handshake failed).
    Authentication(String),
    /// The `kafka` feature is not enabled in this build.
    ///
    /// `KafkaProducer` / `TransactionalProducer` cannot reach a real broker
    /// without the `kafka` cargo feature. Returned by `send`-family methods so
    /// callers fail loudly instead of silently dropping messages onto the
    /// in-process deterministic harness. To use Kafka, build with `--features kafka`.
    FeatureDisabled,
}

/// Native failure from transactional consumer-offset enrollment or its commit.
///
/// This is carried inside the existing [`KafkaError::Io`] variant to preserve
/// exhaustive matches on `KafkaError`. Use [`KafkaError::transaction_failure`]
/// to inspect it. The standard error source chain retains the native error.
/// Flags describe librdkafka's verdict; the transaction owner still requires
/// abort recovery after any failed enrollment, including a retriable failure.
#[derive(Debug)]
pub struct KafkaTransactionFailure {
    retriable: bool,
    abort_required: bool,
    fatal: bool,
    source: Box<dyn std::error::Error + Send + Sync>,
}

impl KafkaTransactionFailure {
    /// Whether the native operation was classified as retriable. This does not
    /// authorize retrying a transaction already fenced for abort recovery.
    #[must_use]
    pub const fn is_retriable(&self) -> bool {
        self.retriable
    }

    /// Whether librdkafka explicitly requires aborting the transaction.
    #[must_use]
    pub const fn requires_abort(&self) -> bool {
        self.abort_required
    }

    /// Whether the producer instance is unusable and must be recreated.
    #[must_use]
    pub const fn is_fatal(&self) -> bool {
        self.fatal
    }
}

impl fmt::Display for KafkaTransactionFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "transactional offset operation failed (retriable={}, abort_required={}, fatal={}): {}",
            self.retriable, self.abort_required, self.fatal, self.source
        )
    }
}

impl std::error::Error for KafkaTransactionFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.source.as_ref())
    }
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
            Self::Authentication(msg) => write!(f, "Kafka authentication failed: {msg}"),
            Self::FeatureDisabled => write!(
                f,
                "Kafka is unavailable: the `kafka` cargo feature is not enabled in this build"
            ),
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
    /// Inspect a native transactional-offset failure without parsing its text.
    /// Ordinary I/O errors and the legacy producer APIs return `None`.
    #[must_use]
    pub fn transaction_failure(&self) -> Option<&KafkaTransactionFailure> {
        match self {
            Self::Io(error) => error.get_ref()?.downcast_ref(),
            _ => None,
        }
    }

    /// Whether this error is transient and may succeed on retry.
    #[must_use]
    pub fn is_transient(&self) -> bool {
        if let Some(error) = self.transaction_failure() {
            return error.is_retriable() && !error.requires_abort() && !error.is_fatal();
        }
        matches!(
            self,
            Self::Io(_) | Self::Broker(_) | Self::QueueFull | Self::Transaction(_)
        )
        // Note: Authentication errors are intentionally NOT transient.
        // Retrying invalid credentials or malformed auth responses wastes resources.
    }

    /// Whether this error indicates a connection-level failure.
    #[must_use]
    pub fn is_connection_error(&self) -> bool {
        if self.transaction_failure().is_some() {
            return false;
        }
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
        // The native flag alone is insufficient: this owner conservatively
        // fences every failed enrollment/commit until abort recovery completes.
        if self.transaction_failure().is_some() {
            return false;
        }
        matches!(self, Self::Io(_) | Self::Broker(_) | Self::QueueFull)
        // Note: Authentication errors are intentionally NOT retryable.
        // Malformed SASL responses should fail fast, not retry with credentials.
    }
}

#[cfg(feature = "kafka")]
#[derive(Debug)]
struct KafkaContext;

#[cfg(feature = "kafka")]
impl ClientContext for KafkaContext {}

#[cfg(feature = "kafka")]
impl ConsumerContext for KafkaContext {}

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

        // A delivery report that has already arrived wins over cancellation.
        // librdkafka delivers an enqueued record regardless; reporting
        // Cancelled for a delivered record made the caller send it again.
        if let Some(value) = state.value.take() {
            state.closed = true;
            state.completed = true;
            state.waker = None;
            return Poll::Ready(value);
        }

        if self.cx.checkpoint().is_err() {
            state.closed = true;
            state.completed = true;
            state.waker = None;
            Poll::Ready(Err(KafkaError::Cancelled))
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
fn rdkafka_error_code(err: &RdKafkaError) -> Option<RDKafkaErrorCode> {
    match err {
        RdKafkaError::AdminOp(code)
        | RdKafkaError::ConsumerCommit(code)
        | RdKafkaError::ConsumerQueueClose(code)
        | RdKafkaError::Flush(code)
        | RdKafkaError::Global(code)
        | RdKafkaError::GroupListFetch(code)
        | RdKafkaError::MessageConsumption(code)
        | RdKafkaError::MessageConsumptionFatal(code)
        | RdKafkaError::MessageProduction(code)
        | RdKafkaError::MetadataFetch(code)
        | RdKafkaError::OffsetFetch(code)
        | RdKafkaError::Rebalance(code)
        | RdKafkaError::SetPartitionOffset(code)
        | RdKafkaError::StoreOffset(code)
        | RdKafkaError::MockCluster(code) => Some(*code),
        RdKafkaError::Transaction(native) => Some(native.code()),
        _ => None,
    }
}

#[cfg(feature = "kafka")]
fn map_rdkafka_error(err: &RdKafkaError, message: Option<&BorrowedMessage<'_>>) -> KafkaError {
    match err {
        RdKafkaError::ClientConfig(result, _, key, _) => {
            KafkaError::Config(redacted_config_message(*result, key))
        }
        RdKafkaError::Canceled => KafkaError::Cancelled,
        _ => {
            if let Some(code) = rdkafka_error_code(err) {
                map_error_code(code, message.map(rdkafka::Message::topic))
            } else {
                // String-only variants (ClientCreation, Subscription, etc.) fall back to message text.
                let err_str = err.to_string();
                if err_str.contains("Authentication")
                    || err_str.contains("SASL")
                    || err_str.contains("authentication")
                    || err_str.contains("Invalid credentials")
                    || err_str.contains("Broker: Authentication failed")
                    || err_str.contains("SASL_PLAINTEXT")
                    || err_str.contains("SASL_SSL")
                {
                    KafkaError::Authentication(err_str)
                } else {
                    KafkaError::Broker(err_str)
                }
            }
        }
    }
}

#[cfg(feature = "kafka")]
fn map_transaction_failure(error: RdKafkaError) -> KafkaError {
    let (retriable, abort_required, fatal) = match &error {
        RdKafkaError::Transaction(native) => (
            native.is_retriable(),
            native.txn_requires_abort(),
            native.is_fatal(),
        ),
        _ => (false, false, false),
    };
    KafkaError::Io(io::Error::other(KafkaTransactionFailure {
        retriable,
        abort_required,
        fatal,
        source: Box::new(error),
    }))
}

/// Further `commit_transaction` calls after a retriable commit failure.
#[cfg(feature = "kafka")]
const COMMIT_RESUME_ATTEMPTS: usize = 3;

/// librdkafka reports a commit it could not finish within its timeout as a
/// retriable error ("retry call to resume"). The only call it then accepts is
/// `commit_transaction` again: an abort is refused while the commit is in
/// progress. Resume the commit a bounded number of times, so a coordinator
/// that recovers within that window yields a definitive outcome instead of a
/// producer that can neither commit nor abort (br-asupersync-lde436).
#[cfg(feature = "kafka")]
fn commit_resuming_retriable_failures(
    mut commit: impl FnMut() -> Result<(), RdKafkaError>,
) -> Result<(), RdKafkaError> {
    let mut result = commit();
    for _ in 0..COMMIT_RESUME_ATTEMPTS {
        match &result {
            Err(RdKafkaError::Transaction(native))
                if native.is_retriable() && !native.txn_requires_abort() && !native.is_fatal() =>
            {
                result = commit();
            }
            _ => break,
        }
    }
    result
}

#[cfg(feature = "kafka")]
pub(super) fn redacted_config_message(result: rdkafka::types::RDKafkaConfRes, key: &str) -> String {
    // Both the raw value and librdkafka's free-form description can contain
    // credentials. Keep only the typed result and the diagnostic property name.
    format!("librdkafka rejected property {key:?} ({result:?}; value: <redacted>)")
}

#[cfg(feature = "kafka")]
fn map_error_code(code: RDKafkaErrorCode, topic: Option<&str>) -> KafkaError {
    match code {
        RDKafkaErrorCode::QueueFull => KafkaError::QueueFull,
        RDKafkaErrorCode::InvalidTopic | RDKafkaErrorCode::UnknownTopic => {
            KafkaError::InvalidTopic(topic.unwrap_or("unknown").to_string())
        }
        // Refused credentials, ACLs or SASL exchanges are never retried; timeouts are (is_timeout).
        RDKafkaErrorCode::Authentication
        | RDKafkaErrorCode::SaslAuthenticationFailed
        | RDKafkaErrorCode::UnsupportedSASLMechanism
        | RDKafkaErrorCode::IllegalSASLState
        | RDKafkaErrorCode::TopicAuthorizationFailed
        | RDKafkaErrorCode::GroupAuthorizationFailed
        | RDKafkaErrorCode::ClusterAuthorizationFailed
        | RDKafkaErrorCode::TransactionalIdAuthorizationFailed
        | RDKafkaErrorCode::DelegationTokenAuthorizationFailed => {
            KafkaError::Authentication(format!("{code:?}"))
        }
        RDKafkaErrorCode::MessageTimedOut
        | RDKafkaErrorCode::RequestTimedOut
        | RDKafkaErrorCode::OperationTimedOut => {
            KafkaError::Io(io::Error::new(io::ErrorKind::TimedOut, format!("{code:?}")))
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

#[cfg_attr(
    not(any(feature = "kafka", test, feature = "test-internals")),
    allow(dead_code)
)]
struct SendRequest<'a> {
    topic: &'a str,
    key: Option<&'a [u8]>,
    payload: Option<&'a [u8]>,
    partition: Option<i32>,
    headers: SendHeaders<'a>,
}

#[derive(Clone, Copy)]
#[cfg_attr(
    not(any(feature = "kafka", test, feature = "test-internals")),
    allow(dead_code)
)]
enum SendHeaders<'a> {
    None,
    Bytes(&'a [(&'a str, &'a [u8])]),
    Nullable(&'a [(&'a str, Option<&'a [u8]>)]),
}

#[cfg(any(feature = "kafka", test, feature = "test-internals"))]
impl<'a> SendHeaders<'a> {
    fn iter(self) -> impl Iterator<Item = (&'a str, Option<&'a [u8]>)> {
        let bytes = match self {
            Self::Bytes(headers) => headers,
            _ => &[],
        };
        let nullable = match self {
            Self::Nullable(headers) => headers,
            _ => &[],
        };
        bytes
            .iter()
            .map(|(key, value)| (*key, Some(*value)))
            .chain(nullable.iter().copied())
    }
}

#[cfg(feature = "kafka")]
fn build_client_config(
    config: &ProducerConfig,
    transactional: Option<&TransactionalConfig>,
) -> ClientConfig {
    let mut client = ClientConfig::new();
    // Raw passthrough first: the typed setters below override any key they
    // own, so typed fields win on conflict (documented on `with_property`).
    for (key, value) in &config.extra_properties {
        client.set(key.as_str(), value.as_str());
    }
    client.set("bootstrap.servers", config.bootstrap_servers.join(","));
    apply_security_config(&mut client, &config.security);
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

#[cfg(any(feature = "kafka", test))]
pub(crate) async fn run_kafka_blocking<F, T>(cx: &Cx, f: F) -> T
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
async fn send_with_producer(
    producer: &ThreadedProducer<KafkaContext>,
    cx: &Cx,
    config: &ProducerConfig,
    request: SendRequest<'_>,
) -> Result<RecordMetadata, KafkaError> {
    cx.checkpoint().map_err(|_| KafkaError::Cancelled)?;

    let payload_size = request.payload.map_or(0, <[u8]>::len);
    if payload_size > config.max_message_size {
        return Err(KafkaError::MessageTooLarge {
            size: payload_size,
            max_size: config.max_message_size,
        });
    }

    let receiver = retry_immediate_send(cx, config, || {
        let (sender, receiver) = delivery_channel(cx);

        let mut record = BaseRecord::with_opaque_to(request.topic, Box::new(sender));
        if let Some(payload) = request.payload {
            record = record.payload(payload);
        }
        if let Some(key) = request.key {
            record = record.key(key);
        }
        if let Some(partition) = request.partition {
            record = record.partition(partition);
        }
        if !matches!(request.headers, SendHeaders::None) {
            let mut owned_headers = OwnedHeaders::new();
            for (key, value) in request.headers.iter() {
                owned_headers = owned_headers.insert(Header { key, value });
            }
            record = record.headers(owned_headers);
        }

        match producer.send(record) {
            Ok(()) => Ok(receiver),
            Err((err, _)) => Err(map_rdkafka_error(&err, None)),
        }
    })
    .await?;

    receiver.await
}

#[cfg(any(feature = "kafka", test))]
fn producer_retry_backoff(config: &ProducerConfig, attempt: u32) -> Duration {
    if config.linger_ms == 0 {
        return Duration::ZERO;
    }

    let base_ms = config.linger_ms;
    let exp = 1_u64 << attempt.min(6);
    Duration::from_millis(base_ms.saturating_mul(exp).min(250))
}

async fn wait_retry_backoff(cx: &Cx, delay: Duration) -> Result<(), KafkaError> {
    if delay.is_zero() {
        cx.checkpoint().map_err(|_| KafkaError::Cancelled)?;
        crate::runtime::yield_now().await;
        return cx.checkpoint().map_err(|_| KafkaError::Cancelled);
    }

    let mut sleeper = cx.timer_driver().map_or_else(
        || crate::time::sleep(crate::time::wall_now(), delay),
        |driver| {
            let deadline = driver
                .now()
                .saturating_add_nanos(delay.as_nanos().min(u128::from(u64::MAX)) as u64);
            crate::time::Sleep::with_timer_driver(deadline, driver)
        },
    );
    std::future::poll_fn(|task_cx| {
        if cx.checkpoint().is_err() {
            return std::task::Poll::Ready(Err(KafkaError::Cancelled));
        }
        std::pin::Pin::new(&mut sleeper)
            .poll(task_cx)
            .map(|()| Ok(()))
    })
    .await
}

#[cfg(any(feature = "kafka", test))]
async fn retry_immediate_send<T, F>(
    cx: &Cx,
    config: &ProducerConfig,
    mut attempt_send: F,
) -> Result<T, KafkaError>
where
    F: FnMut() -> Result<T, KafkaError>,
{
    let mut attempt = 0;
    loop {
        cx.checkpoint().map_err(|_| KafkaError::Cancelled)?;

        match attempt_send() {
            Ok(value) => return Ok(value),
            Err(err) if err.is_retryable() && attempt < config.retries => {
                let delay = producer_retry_backoff(config, attempt);
                attempt = attempt.saturating_add(1);
                wait_retry_backoff(cx, delay).await?;
            }
            Err(err) => return Err(err),
        }
    }
}

#[cfg(all(not(feature = "kafka"), any(test, feature = "test-internals")))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DeterministicBrokerRecord {
    pub topic: String,
    pub partition: i32,
    pub key: Option<Vec<u8>>,
    pub payload: Option<Vec<u8>>,
    pub timestamp: Option<i64>,
    pub headers: Vec<(String, Option<Vec<u8>>)>,
}

#[cfg(all(not(feature = "kafka"), any(test, feature = "test-internals")))]
#[derive(Debug, Default)]
struct DeterministicBrokerState {
    partitions: BTreeMap<(String, i32), Vec<DeterministicBrokerRecord>>,
}

#[cfg(all(not(feature = "kafka"), any(test, feature = "test-internals")))]
/// Harness-only deterministic in-process broker shared by the fallback
/// producer and consumer paths when the real Kafka feature is disabled.
#[derive(Debug, Default)]
struct DeterministicBroker {
    state: Mutex<DeterministicBrokerState>,
    notify: Notify,
}

#[cfg(all(not(feature = "kafka"), any(test, feature = "test-internals")))]
static DETERMINISTIC_BROKER: OnceLock<DeterministicBroker> = OnceLock::new();

#[cfg(all(not(feature = "kafka"), feature = "test-internals"))]
static DETERMINISTIC_BROKER_TEST_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

#[cfg(all(not(feature = "kafka"), any(test, feature = "test-internals")))]
fn deterministic_broker() -> &'static DeterministicBroker {
    // PRODUCTION SAFETY: Block the deterministic harness in production builds.
    // It should only run in this crate's tests and debug-only diagnostics.
    #[cfg(not(any(test, debug_assertions)))]
    {
        panic!(
            "CRITICAL: deterministic Kafka harness attempted to run in production build. \
             It lacks real broker durability and can cause message loss in \
             payment/transaction paths. \
             Enable the 'kafka' feature for production use or ensure debug_assertions are enabled."
        );
    }

    #[cfg(any(test, debug_assertions))]
    {
        DETERMINISTIC_BROKER.get_or_init(DeterministicBroker::default)
    }
}

#[cfg(all(not(feature = "kafka"), any(test, feature = "test-internals")))]
pub(crate) fn deterministic_broker_notify() -> &'static Notify {
    &deterministic_broker().notify
}

#[cfg(all(not(feature = "kafka"), any(test, feature = "test-internals")))]
/// Return the current end offset for a deterministic harness topic partition.
pub fn deterministic_broker_end_offset(topic: &str, partition: i32) -> i64 {
    let state = deterministic_broker().state.lock();
    state
        .partitions
        .get(&(topic.to_string(), partition))
        .map_or(0, |partition_log| {
            i64::try_from(partition_log.len()).unwrap_or(i64::MAX)
        })
}

#[cfg(all(not(feature = "kafka"), any(test, feature = "test-internals")))]
pub(crate) fn deterministic_broker_fetch(
    topic: &str,
    partition: i32,
    offset: i64,
) -> Option<DeterministicBrokerRecord> {
    if offset < 0 {
        return None;
    }

    let state = deterministic_broker().state.lock();
    state
        .partitions
        .get(&(topic.to_string(), partition))
        .and_then(|partition_log| {
            usize::try_from(offset)
                .ok()
                .and_then(|index| partition_log.get(index).cloned())
        })
}

#[cfg(all(not(feature = "kafka"), any(test, feature = "test-internals")))]
#[allow(dead_code)]
pub(crate) fn deterministic_broker_publish(record: DeterministicBrokerRecord) -> RecordMetadata {
    // PRODUCTION SAFETY: Additional guard for critical payment/transaction topics
    if is_critical_production_topic(&record.topic) {
        #[cfg(not(any(test, debug_assertions)))]
        {
            panic!(
                "CRITICAL: attempted to publish to production topic '{}' using deterministic Kafka harness. \
                 This can cause message loss in payment/transaction systems. \
                 Use real Kafka broker with the 'kafka' feature enabled.",
                record.topic
            );
        }

        // In test builds, log the high-risk operation.
        #[cfg(any(test, debug_assertions))]
        eprintln!(
            "WARNING: publishing to critical topic '{}' using deterministic Kafka harness. \
             This is safe only in test environments.",
            record.topic
        );
    }

    deterministic_broker_publish_batch(vec![record])
        .into_iter()
        .next()
        .expect("single-record publish must return metadata")
}

#[cfg(all(not(feature = "kafka"), any(test, feature = "test-internals")))]
fn deterministic_broker_publish_batch(
    records: Vec<DeterministicBrokerRecord>,
) -> Vec<RecordMetadata> {
    if records.is_empty() {
        return Vec::new();
    }

    let metadata = {
        let mut state = deterministic_broker().state.lock();
        let mut metadata = Vec::with_capacity(records.len());

        for record in records {
            let partition_log = state
                .partitions
                .entry((record.topic.clone(), record.partition))
                .or_default();
            let offset = i64::try_from(partition_log.len()).unwrap_or(i64::MAX);
            metadata.push(RecordMetadata {
                topic: record.topic.clone(),
                partition: record.partition,
                offset,
                timestamp: record.timestamp,
            });
            partition_log.push(record);
        }

        metadata
    };

    deterministic_broker().notify.notify_waiters();
    metadata
}

#[cfg(all(not(feature = "kafka"), feature = "test-internals"))]
/// Reset the deterministic broker state used by integration tests.
pub fn reset_deterministic_broker_for_tests() {
    if let Some(broker) = DETERMINISTIC_BROKER.get() {
        broker.state.lock().partitions.clear();
        broker.notify.notify_waiters();
    }
}

#[cfg(all(not(feature = "kafka"), feature = "test-internals"))]
#[allow(dead_code)] // Guard held for test serialization — not read, just held
/// Test guard that serializes access to the process-global deterministic broker.
pub struct DeterministicBrokerTestGuard(parking_lot::MutexGuard<'static, ()>);

#[cfg(all(not(feature = "kafka"), feature = "test-internals"))]
impl Drop for DeterministicBrokerTestGuard {
    fn drop(&mut self) {
        reset_deterministic_broker_for_tests();
    }
}

#[cfg(all(not(feature = "kafka"), feature = "test-internals"))]
/// Acquire exclusive test access to the deterministic broker and clear it.
pub fn lock_deterministic_broker_for_tests() -> DeterministicBrokerTestGuard {
    let lock = DETERMINISTIC_BROKER_TEST_LOCK.get_or_init(|| Mutex::new(()));
    let guard = lock.lock();

    // The harness broker is global state shared across producer and consumer
    // unit tests, so keep one test in the lane at a time and reset state on
    // both entry and exit.
    reset_deterministic_broker_for_tests();

    DeterministicBrokerTestGuard(guard)
}

fn validate_topic(topic: &str) -> Result<(), KafkaError> {
    let topic = topic.trim();
    if topic.is_empty() {
        return Err(KafkaError::InvalidTopic(topic.to_string()));
    }
    Ok(())
}

#[cfg(any(feature = "kafka", test))]
fn kafka_client_consumer_group_id(
    config: &ProducerConfig,
    topic: &str,
) -> Result<String, KafkaError> {
    validate_topic(topic)?;

    let client_id = config
        .client_id
        .as_deref()
        .map(str::trim)
        .filter(|client_id| !client_id.is_empty())
        .ok_or_else(|| {
            KafkaError::Config(
                "KafkaClient::consumer requires ProducerConfig::client_id(...) so each caller joins an explicit consumer realm instead of the shared default group".to_string(),
            )
        })?;

    Ok(format!("asupersync-consumer-{client_id}-{topic}"))
}

#[cfg(all(not(feature = "kafka"), any(test, feature = "test-internals")))]
/// Check if a topic contains critical production data that should never use the deterministic harness.
fn is_critical_production_topic(topic: &str) -> bool {
    // Payment and transaction topics are critical - message loss = financial loss
    topic.contains("payment")
        || topic.contains("transaction")
        || topic.contains("billing")
        || topic.contains("charge")
        || topic.contains("refund")
        || topic.contains("settle")
        || topic.contains("wallet")
        || topic.contains("invoice")
        || topic.contains("subscription")
        || topic.starts_with("fabric.payment.")
        || topic.starts_with("fabric.billing.")
        || topic.starts_with("fabric.transaction.")
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

/// Whether a producer configuration requires real broker-backed Kafka support.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum KafkaFeatureRequirement {
    /// Kafka is optional for this configuration. Non-test builds without the
    /// `kafka` feature still return `FeatureDisabled` from broker operations.
    #[default]
    Optional,
    /// Kafka is mandatory for this configuration. Validation fails if the
    /// crate was built without the `kafka` feature.
    Required,
}

impl KafkaFeatureRequirement {
    /// Stable operator-facing label for diagnostics and artifacts.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Optional => "optional",
            Self::Required => "required",
        }
    }
}

fn bootstrap_server_host(endpoint: &str) -> &str {
    if let Some(rest) = endpoint.strip_prefix('[') {
        return rest.split_once(']').map_or(endpoint, |(host, _)| host);
    }

    endpoint.rsplit_once(':').map_or(endpoint, |(host, _)| host)
}

pub(crate) fn is_loopback_bootstrap_server(endpoint: &str) -> bool {
    let host = bootstrap_server_host(endpoint).trim();
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }

    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        match ip {
            std::net::IpAddr::V4(v4) => v4.is_loopback(),
            std::net::IpAddr::V6(v6) => {
                // Check for standard IPv6 loopback
                if v6.is_loopback() {
                    return true;
                }
                // SECURITY: Check for IPv4-mapped IPv6 addresses (::ffff:x.x.x.x)
                // These should NOT be considered loopback even if the mapped IPv4 is loopback,
                // because they can be used to bypass validation for remote addresses.
                if let Some(mapped_v4) = v6.to_ipv4_mapped() {
                    // IPv4-mapped IPv6 addresses are only loopback if the mapped IPv4 is loopback
                    // AND the original address was explicitly ::ffff:127.0.0.1 style
                    mapped_v4.is_loopback()
                } else {
                    false
                }
            }
        }
    } else {
        false
    }
}

/// TLS settings for Kafka clients.
#[derive(Clone, PartialEq, Eq, Default)]
pub struct KafkaTlsConfig {
    /// File or directory path to CA certificates used to verify the broker.
    pub ca_location: Option<String>,
    /// Client certificate path for mutual TLS.
    pub certificate_location: Option<String>,
    /// Client private key path for mutual TLS.
    pub key_location: Option<String>,
    key_password: Option<String>,
}

impl fmt::Debug for KafkaTlsConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KafkaTlsConfig")
            .field("ca_location", &self.ca_location)
            .field("certificate_location", &self.certificate_location)
            .field("key_location", &self.key_location)
            .field(
                "key_password",
                &self.key_password.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

impl KafkaTlsConfig {
    /// Create an empty TLS config. librdkafka will use its platform CA lookup
    /// unless `ca_location` is set explicitly.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the CA certificate file or directory.
    #[must_use]
    pub fn ca_location(mut self, location: impl Into<String>) -> Self {
        self.ca_location = Some(location.into());
        self
    }

    /// Set the client certificate path for mutual TLS.
    #[must_use]
    pub fn certificate_location(mut self, location: impl Into<String>) -> Self {
        self.certificate_location = Some(location.into());
        self
    }

    /// Set the client private key path for mutual TLS.
    #[must_use]
    pub fn key_location(mut self, location: impl Into<String>) -> Self {
        self.key_location = Some(location.into());
        self
    }

    /// Set the client private key password for mutual TLS.
    #[must_use]
    pub fn key_password(mut self, password: impl Into<String>) -> Self {
        self.key_password = Some(password.into());
        self
    }
}

/// SASL mechanisms exposed by the Kafka client.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KafkaSaslMechanism {
    /// SCRAM with SHA-256.
    ScramSha256,
    /// SCRAM with SHA-512.
    ScramSha512,
}

impl KafkaSaslMechanism {
    #[cfg(feature = "kafka")]
    fn as_librdkafka_str(self) -> &'static str {
        match self {
            Self::ScramSha256 => "SCRAM-SHA-256",
            Self::ScramSha512 => "SCRAM-SHA-512",
        }
    }
}

/// Secure password storage for SASL credentials.
///
/// **Sensitive material.** Derives [`ZeroizeOnDrop`] which provides secure
/// memory cleanup with compiler-resistant zeroization. When this struct is
/// dropped, the password bytes are overwritten with zeros to prevent them
/// from remaining in memory where they could be accessed by memory dumps or
/// other inspection techniques.
#[derive(Clone, PartialEq, Eq, ZeroizeOnDrop)]
struct SecureSaslPassword {
    password: String,
}

impl SecureSaslPassword {
    /// Create a new secure password from a string.
    fn new(password: impl Into<String>) -> Self {
        Self {
            password: password.into(),
        }
    }

    /// Get a reference to the password string for use with rdkafka.
    ///
    /// SECURITY: This method provides access to the plaintext password.
    /// The caller must ensure the returned reference is not stored or
    /// copied beyond the immediate scope where it's needed.
    fn as_str(&self) -> &str {
        &self.password
    }
}

impl fmt::Debug for SecureSaslPassword {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecureSaslPassword")
            .field("password", &"<redacted>")
            .finish()
    }
}

/// SASL/SCRAM credentials for Kafka clients.
///
/// The Kafka feature delegates SCRAM handshakes to librdkafka today. Any
/// repo-local SCRAM implementation must reject salts shorter than 8 bytes,
/// reject iteration counts outside `4096..=65536`, verify server-final proofs
/// with a constant-time comparison, and keep authentication on `SASL_SSL`
/// instead of introducing a plaintext SASL transport.
///
/// **SECURITY**: Password is stored using `SecureSaslPassword`, which implements
/// [`ZeroizeOnDrop`] to securely clear sensitive data from memory when dropped.
#[derive(Clone, PartialEq, Eq)]
pub struct KafkaSaslConfig {
    /// SCRAM mechanism.
    pub mechanism: KafkaSaslMechanism,
    /// SASL username.
    pub username: String,
    /// SASL password (securely zeroized on drop).
    password: SecureSaslPassword,
    /// TLS settings used with SASL_SSL.
    pub tls: KafkaTlsConfig,
}

impl fmt::Debug for KafkaSaslConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KafkaSaslConfig")
            .field("mechanism", &self.mechanism)
            .field("username", &self.username)
            .field("password", &"<redacted>")
            .field("tls", &self.tls)
            .finish()
    }
}

impl KafkaSaslConfig {
    /// Create SCRAM-SHA-256 credentials.
    #[must_use]
    pub fn scram_sha_256(username: impl Into<String>, password: impl Into<String>) -> Self {
        Self {
            mechanism: KafkaSaslMechanism::ScramSha256,
            username: username.into(),
            password: SecureSaslPassword::new(password),
            tls: KafkaTlsConfig::default(),
        }
    }

    /// Create SCRAM-SHA-512 credentials.
    #[must_use]
    pub fn scram_sha_512(username: impl Into<String>, password: impl Into<String>) -> Self {
        Self {
            mechanism: KafkaSaslMechanism::ScramSha512,
            username: username.into(),
            password: SecureSaslPassword::new(password),
            tls: KafkaTlsConfig::default(),
        }
    }

    /// Attach TLS settings to SASL_SSL.
    #[must_use]
    pub fn with_tls(mut self, tls: KafkaTlsConfig) -> Self {
        self.tls = tls;
        self
    }

    fn validate(&self) -> Result<(), KafkaError> {
        if self.username.trim().is_empty() {
            return Err(KafkaError::Config(
                "Kafka SASL username cannot be empty".to_string(),
            ));
        }
        if self.password.as_str().trim().is_empty() {
            return Err(KafkaError::Config(
                "Kafka SASL password cannot be empty".to_string(),
            ));
        }
        Ok(())
    }
}

/// Security transport for Kafka clients.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum KafkaSecurityConfig {
    /// Plaintext transport. Valid only for loopback brokers unless the
    /// test/debug-only insecure bypass is enabled.
    #[default]
    Plaintext,
    /// TLS transport without SASL.
    Tls(KafkaTlsConfig),
    /// SASL/SCRAM over TLS. SASL_PLAINTEXT is intentionally not exposed.
    SaslSsl(KafkaSaslConfig),
}

impl KafkaSecurityConfig {
    #[must_use]
    pub(crate) fn is_remote_secure(&self) -> bool {
        matches!(self, Self::Tls(_) | Self::SaslSsl(_))
    }

    pub(crate) fn validate(&self) -> Result<(), KafkaError> {
        match self {
            Self::Plaintext | Self::Tls(_) => Ok(()),
            Self::SaslSsl(config) => config.validate(),
        }
    }
}

#[cfg(feature = "kafka")]
fn apply_tls_config(client: &mut ClientConfig, tls: &KafkaTlsConfig) {
    if let Some(location) = &tls.ca_location {
        client.set("ssl.ca.location", location);
    }
    if let Some(location) = &tls.certificate_location {
        client.set("ssl.certificate.location", location);
    }
    if let Some(location) = &tls.key_location {
        client.set("ssl.key.location", location);
    }
    if let Some(password) = &tls.key_password {
        client.set("ssl.key.password", password);
    }
}

#[cfg(feature = "kafka")]
pub(crate) fn apply_security_config(client: &mut ClientConfig, security: &KafkaSecurityConfig) {
    match security {
        KafkaSecurityConfig::Plaintext => {
            client.set("security.protocol", "plaintext");
        }
        KafkaSecurityConfig::Tls(tls) => {
            client.set("security.protocol", "ssl");
            apply_tls_config(client, tls);
        }
        KafkaSecurityConfig::SaslSsl(sasl) => {
            client.set("security.protocol", "sasl_ssl");
            client.set("sasl.mechanisms", sasl.mechanism.as_librdkafka_str());
            client.set("sasl.username", &sasl.username);
            client.set("sasl.password", sasl.password.as_str());
            apply_tls_config(client, &sasl.tls);
        }
    }
}

/// Formats caller-provided property names while hiding every raw value.
///
/// Raw extensions can carry credentials under names unknown to this version,
/// so a secret-key denylist cannot safely determine which values to print.
pub(super) struct RedactedProperties<'a>(pub(super) &'a [(String, String)]);

impl fmt::Debug for RedactedProperties<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list()
            .entries(self.0.iter().map(|(key, _)| (key, "<redacted>")))
            .finish()
    }
}

/// Configuration for Kafka producer.
///
/// `Debug` retains typed settings and raw property names, but redacts every
/// raw property value. Keep credentials in values, never in property names.
#[derive(Clone)]
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
    /// Transport security for Kafka broker connections.
    pub security: KafkaSecurityConfig,
    /// Whether this config requires the real `kafka` cargo feature.
    pub feature_requirement: KafkaFeatureRequirement,
    /// Internal test/debug-only opt-in for PLAINTEXT / unauthenticated remote brokers.
    ///
    /// The secure default is fail-closed for non-loopback plaintext bootstrap
    /// servers.
    /// Keep this private so release callers cannot enable the bypass through a
    /// struct literal.
    allow_insecure_transport_for_testing: bool,
    /// Internal opt-in for the no-feature deterministic broker in downstream
    /// integration tests.
    #[cfg(any(test, feature = "test-internals"))]
    allow_deterministic_broker_for_testing: bool,
    /// Raw librdkafka properties applied before the typed fields
    /// ([`ProducerConfig::with_property`]), in insertion order.
    extra_properties: Vec<(String, String)>,
}

impl fmt::Debug for ProducerConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut debug = f.debug_struct("ProducerConfig");
        debug
            .field("bootstrap_servers", &self.bootstrap_servers)
            .field("client_id", &self.client_id)
            .field("batch_size", &self.batch_size)
            .field("linger_ms", &self.linger_ms)
            .field("compression", &self.compression)
            .field("enable_idempotence", &self.enable_idempotence)
            .field("acks", &self.acks)
            .field("retries", &self.retries)
            .field("request_timeout", &self.request_timeout)
            .field("max_message_size", &self.max_message_size)
            .field("security", &self.security)
            .field("feature_requirement", &self.feature_requirement)
            .field(
                "allow_insecure_transport_for_testing",
                &self.allow_insecure_transport_for_testing,
            );
        #[cfg(any(test, feature = "test-internals"))]
        debug.field(
            "allow_deterministic_broker_for_testing",
            &self.allow_deterministic_broker_for_testing,
        );
        debug
            .field(
                "extra_properties",
                &RedactedProperties(&self.extra_properties),
            )
            .finish()
    }
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
            security: KafkaSecurityConfig::default(),
            feature_requirement: KafkaFeatureRequirement::default(),
            allow_insecure_transport_for_testing: false,
            #[cfg(any(test, feature = "test-internals"))]
            allow_deterministic_broker_for_testing: false,
            extra_properties: Vec::new(),
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

    /// Forward a raw librdkafka property.
    ///
    /// Applied in insertion order BEFORE the typed fields, so a typed field
    /// always wins over a raw property with the same key; a later call for
    /// the same key overrides an earlier one. Unknown keys are rejected by
    /// librdkafka when the producer is created.
    ///
    /// `Debug` redacts all raw values, including non-secret values. Property
    /// names remain visible and must not contain credentials.
    /// Native configuration rejection reports the property name and result
    /// code, without the value or free-form native error description.
    #[must_use]
    pub fn with_property(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.set_property(key, value);
        self
    }

    /// In-place form of [`Self::with_property`].
    pub fn set_property(&mut self, key: impl Into<String>, value: impl Into<String>) {
        let key = key.into();
        let value = value.into();
        if let Some(slot) = self
            .extra_properties
            .iter_mut()
            .find(|(existing, _)| *existing == key)
        {
            slot.1 = value;
        } else {
            self.extra_properties.push((key, value));
        }
    }

    /// The raw properties set through [`Self::with_property`], in the order
    /// they are applied.
    ///
    /// Unlike this configuration's `Debug` output, this explicit accessor
    /// returns the original values, which may contain credentials.
    #[must_use]
    pub fn extra_properties(&self) -> &[(String, String)] {
        &self.extra_properties
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

    /// Set Kafka broker transport security.
    #[must_use]
    pub fn security(mut self, security: KafkaSecurityConfig) -> Self {
        self.security = security;
        self
    }

    /// Set whether this configuration requires real Kafka feature support.
    #[must_use]
    pub const fn feature_requirement(mut self, requirement: KafkaFeatureRequirement) -> Self {
        self.feature_requirement = requirement;
        self
    }

    /// Fail validation when the crate is built without the real `kafka` feature.
    #[must_use]
    pub const fn require_kafka_feature(mut self) -> Self {
        self.feature_requirement = KafkaFeatureRequirement::Required;
        self
    }

    /// Keep Kafka optional for this configuration.
    #[must_use]
    pub const fn optional_kafka_feature(mut self) -> Self {
        self.feature_requirement = KafkaFeatureRequirement::Optional;
        self
    }

    /// Require TLS for Kafka broker transport.
    #[must_use]
    pub fn tls(self, tls: KafkaTlsConfig) -> Self {
        self.security(KafkaSecurityConfig::Tls(tls))
    }

    /// Require SASL/SCRAM-SHA-256 over TLS for Kafka broker transport.
    #[must_use]
    pub fn sasl_scram_sha_256(
        self,
        username: impl Into<String>,
        password: impl Into<String>,
    ) -> Self {
        self.security(KafkaSecurityConfig::SaslSsl(
            KafkaSaslConfig::scram_sha_256(username, password),
        ))
    }

    /// Require SASL/SCRAM-SHA-512 over TLS for Kafka broker transport.
    #[must_use]
    pub fn sasl_scram_sha_512(
        self,
        username: impl Into<String>,
        password: impl Into<String>,
    ) -> Self {
        self.security(KafkaSecurityConfig::SaslSsl(
            KafkaSaslConfig::scram_sha_512(username, password),
        ))
    }

    /// Scary test/debug-only opt-in for remote PLAINTEXT / unauthenticated brokers.
    ///
    /// This setter is intentionally unavailable in release builds so
    /// production callers cannot compile with a remote plaintext-broker bypass.
    #[cfg(any(test, debug_assertions))]
    #[must_use]
    pub const fn allow_insecure_transport_for_testing(mut self, allow: bool) -> Self {
        self.allow_insecure_transport_for_testing = allow;
        self
    }

    /// Opt into the deterministic no-feature broker for downstream tests.
    ///
    /// Crate unit tests use the deterministic broker automatically, but
    /// integration tests compile as downstream consumers and must opt in
    /// explicitly so default broker operations keep failing closed.
    #[cfg(any(test, feature = "test-internals"))]
    #[must_use]
    pub const fn allow_deterministic_broker_for_testing(mut self, allow: bool) -> Self {
        self.allow_deterministic_broker_for_testing = allow;
        self
    }

    #[cfg(not(feature = "kafka"))]
    fn deterministic_broker_allowed_for_testing(&self) -> bool {
        #[cfg(test)]
        {
            true
        }
        #[cfg(all(not(test), feature = "test-internals"))]
        {
            self.allow_deterministic_broker_for_testing
        }
        #[cfg(all(not(test), not(feature = "test-internals")))]
        {
            false
        }
    }

    /// Operator-facing feature availability diagnostic.
    #[must_use]
    pub fn kafka_feature_diagnostic(&self) -> &'static str {
        #[cfg(feature = "kafka")]
        {
            "Kafka cargo feature is enabled; real broker integration is available"
        }
        #[cfg(not(feature = "kafka"))]
        {
            match self.feature_requirement {
                KafkaFeatureRequirement::Optional => {
                    "Kafka cargo feature is optional for this config and is not enabled; \
                     non-test broker operations return FeatureDisabled"
                }
                KafkaFeatureRequirement::Required => {
                    "Kafka cargo feature is required by this config but is not enabled; \
                     rebuild with --features kafka"
                }
            }
        }
    }

    fn validate_feature_requirement(&self) -> Result<(), KafkaError> {
        #[cfg(not(feature = "kafka"))]
        {
            if self.feature_requirement == KafkaFeatureRequirement::Required {
                return Err(KafkaError::FeatureDisabled);
            }
        }
        Ok(())
    }

    /// Validate the configuration.
    pub fn validate(&self) -> Result<(), KafkaError> {
        self.validate_feature_requirement()?;
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
        self.security.validate()?;
        if !self.allow_insecure_transport_for_testing && !self.security.is_remote_secure() {
            for server in &self.bootstrap_servers {
                if !is_loopback_bootstrap_server(server) {
                    return Err(KafkaError::Config(format!(
                        "remote Kafka bootstrap server '{server}' is rejected by default: \
                         configure TLS or SASL_SSL SCRAM security for non-loopback brokers"
                    )));
                }
            }
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
    // Also used while a native initialization or recovery owns the producer.
    Finalizing,
    NeedsAbortRecovery,
}

#[derive(Debug, Default)]
struct TransactionalProducerState {
    phase: TransactionPhase,
    generation: u64,
    operation_in_flight: bool,
    abandoned: bool,
    pending_offsets: Option<PreparedTransactionOffsets>,
    #[cfg(feature = "kafka")]
    initialized: bool,
    #[cfg(all(not(feature = "kafka"), any(test, feature = "test-internals")))]
    staged_records: Vec<DeterministicBrokerRecord>,
}

/// Kafka producer with Cx integration.
///
/// With the `kafka` feature enabled this wraps a real `rdkafka` producer.
/// Without it, the producer talks to the harness-only in-process broker used
/// for tests and contract validation; it is not a production Kafka transport.
pub struct KafkaProducer {
    config: ProducerConfig,
    closed: AtomicBool,
    active_ops: AtomicUsize,
    op_notify: Notify,
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
            active_ops: AtomicUsize::new(0),
            op_notify: Notify::new(),
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
    pub async fn send(
        &self,
        cx: &Cx,
        topic: &str,
        key: Option<&[u8]>,
        payload: &[u8],
        partition: Option<i32>,
    ) -> Result<RecordMetadata, KafkaError> {
        self.send_nullable(cx, topic, key, Some(payload), partition)
            .await
    }

    /// Send a message with headers.
    ///
    /// # Arguments
    /// * `cx` - Cancellation context
    /// * `topic` - Target topic name
    /// * `key` - Optional message key for partitioning
    /// * `payload` - Message payload
    /// * `headers` - Key-value header pairs
    pub async fn send_with_headers(
        &self,
        cx: &Cx,
        topic: &str,
        key: Option<&[u8]>,
        payload: &[u8],
        headers: &[(&str, &[u8])],
    ) -> Result<RecordMetadata, KafkaError> {
        self.send_request(
            cx,
            SendRequest {
                topic,
                key,
                payload: Some(payload),
                partition: None,
                headers: SendHeaders::Bytes(headers),
            },
        )
        .await
    }

    /// Send a Kafka value or a tombstone.
    ///
    /// `None` sends a null payload; on a compacted topic, use the key of the
    /// value to delete. `Some(&[])` sends an ordinary empty payload. Routing,
    /// delivery acknowledgements, cancellation, retries and size limits use
    /// the same path as [`Self::send`]. A null value is not a client-side delete:
    /// the broker's compaction policy and consuming applications determine its
    /// effect.
    pub async fn send_nullable(
        &self,
        cx: &Cx,
        topic: &str,
        key: Option<&[u8]>,
        payload: Option<&[u8]>,
        partition: Option<i32>,
    ) -> Result<RecordMetadata, KafkaError> {
        self.send_request(
            cx,
            SendRequest {
                topic,
                key,
                payload,
                partition,
                headers: SendHeaders::None,
            },
        )
        .await
    }

    /// Send a nullable payload with ordered, nullable headers.
    ///
    /// Duplicate header names, null values and empty values are preserved on
    /// the wire. `partition` overrides routing exactly as in [`Self::send`].
    /// Consume these records with
    /// [`KafkaConsumer::poll_nullable`](super::kafka_consumer::KafkaConsumer::poll_nullable)
    /// to retain every null versus empty distinction.
    pub async fn send_nullable_with_headers(
        &self,
        cx: &Cx,
        topic: &str,
        key: Option<&[u8]>,
        payload: Option<&[u8]>,
        headers: &[(&str, Option<&[u8]>)],
        partition: Option<i32>,
    ) -> Result<RecordMetadata, KafkaError> {
        self.send_request(
            cx,
            SendRequest {
                topic,
                key,
                payload,
                partition,
                headers: SendHeaders::Nullable(headers),
            },
        )
        .await
    }

    #[allow(clippy::unused_async)]
    async fn send_request(
        &self,
        cx: &Cx,
        request: SendRequest<'_>,
    ) -> Result<RecordMetadata, KafkaError> {
        cx.checkpoint().map_err(|_| KafkaError::Cancelled)?;
        validate_topic(request.topic)?;

        let payload_size = request.payload.map_or(0, <[u8]>::len);
        if payload_size > self.config.max_message_size {
            return Err(KafkaError::MessageTooLarge {
                size: payload_size,
                max_size: self.config.max_message_size,
            });
        }

        let _op_guard = self.begin_operation()?;

        #[cfg(feature = "kafka")]
        {
            send_with_producer(
                &self.producer,
                cx,
                &self.config,
                request,
            )
            .await
        }

        // Only the opt-in test harness may use the deterministic broker;
        // non-Kafka production builds fail closed (br-asupersync-w2p2a0).
        #[cfg(all(not(feature = "kafka"), any(test, feature = "test-internals")))]
        {
            if !self.config.deterministic_broker_allowed_for_testing() {
                return Err(KafkaError::FeatureDisabled);
            }
            Ok(deterministic_broker_publish(DeterministicBrokerRecord {
                topic: request.topic.to_string(),
                partition: request.partition.unwrap_or(0),
                key: request.key.map(std::borrow::ToOwned::to_owned),
                payload: request.payload.map(std::borrow::ToOwned::to_owned),
                timestamp: None,
                headers: request.headers
                    .iter()
                    .map(|(key, value)| (key.to_owned(), value.map(std::borrow::ToOwned::to_owned)))
                    .collect(),
            }))
        }
        #[cfg(all(not(feature = "kafka"), not(any(test, feature = "test-internals"))))]
        {
            Err(KafkaError::FeatureDisabled)
        }
    }

    /// Flush all pending messages.
    ///
    /// Waits until all messages in the queue are sent or the timeout expires.
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
                if self.active_ops.load(Ordering::Acquire) == 0
                    && self.producer.in_flight_count() == 0
                {
                    break;
                }
                if remaining.is_zero() {
                    return Err(KafkaError::Broker("flush timeout elapsed".to_string()));
                }
                let tick = remaining.min(Duration::from_millis(10));
                // ThreadedProducer already owns a dedicated librdkafka polling
                // thread. Polling it here would block this async executor thread
                // for up to `tick`; yield through the runtime timer instead.
                wait_retry_backoff(cx, tick).await?;
                if remaining <= tick {
                    remaining = Duration::ZERO;
                } else {
                    remaining -= tick;
                }
            }
            Ok(())
        }

        #[cfg(not(feature = "kafka"))]
        {
            let mut remaining = timeout;
            while self.active_ops.load(Ordering::Acquire) != 0 {
                cx.checkpoint().map_err(|_| KafkaError::Cancelled)?;
                if remaining.is_zero() {
                    return Err(KafkaError::Broker("flush timeout elapsed".to_string()));
                }
                let tick = remaining.min(Duration::from_millis(10));
                wait_retry_backoff(cx, tick).await?;
                if remaining <= tick {
                    remaining = Duration::ZERO;
                } else {
                    remaining -= tick;
                }
            }
            Ok(())
        }
    }

    fn begin_operation(&self) -> Result<KafkaProducerOperationGuard<'_>, KafkaError> {
        loop {
            if self.closed.load(Ordering::Acquire) {
                return Err(KafkaError::Config("producer is closed".to_string()));
            }

            self.active_ops.fetch_add(1, Ordering::AcqRel);
            if !self.closed.load(Ordering::Acquire) {
                return Ok(KafkaProducerOperationGuard { producer: self });
            }

            if self.active_ops.fetch_sub(1, Ordering::AcqRel) == 1 {
                self.op_notify.notify_waiters();
            }
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

struct KafkaProducerOperationGuard<'a> {
    producer: &'a KafkaProducer,
}

impl Drop for KafkaProducerOperationGuard<'_> {
    fn drop(&mut self) {
        if self.producer.active_ops.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.producer.op_notify.notify_waiters();
        }
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
    state: Arc<Mutex<TransactionalProducerState>>,
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
            state: Arc::new(Mutex::new(TransactionalProducerState::default())),
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
        #[cfg(not(feature = "kafka"))]
        if !self
            .config
            .producer
            .deterministic_broker_allowed_for_testing()
        {
            return Err(KafkaError::FeatureDisabled);
        }
        let generation = self.activate_transaction()?;

        // br-asupersync-tx3wq9: guard the window between activate_transaction()
        // (Idle→Active) and the constructed Transaction taking over the
        // lifecycle. If the ambient Cx is cancelled while the begin op below is
        // in flight, this whole future is DROPPED: neither the Err reset nor the
        // `Ok(Transaction { .. })` below runs, so nothing would reset the phase
        // and it stays wedged in Active forever — every later begin_transaction
        // then returns "transaction already active", and recover_abandoned_
        // transaction (which only heals NeedsAbortRecovery) can never fix it.
        // While native work runs, Drop only marks this generation abandoned.
        // The operation guard publishes recovery after it actually finishes.
        // If completion wins first, the activation guard poisons only its own
        // Active generation. A discarded, never-started begin restores Idle.
        let mut activation = TransactionActivationGuard::armed(self);

        #[cfg(feature = "kafka")]
        {
            let operation = TransactionOperationGuard::claim(
                &self.state,
                generation,
                TransactionOperation::Begin,
            )?;
            let producer = self.producer.clone();
            if let Err(err) = run_owned_transaction_op(cx, operation, move || {
                producer
                    .begin_transaction()
                    .map_err(|err| map_rdkafka_error(&err, None))
            })
            .await
            {
                activation.disarm();
                return Err(err);
            }
        }

        // Success: the returned Transaction owns the lifecycle from here (its own
        // Drop resets the phase if it is neither committed nor aborted).
        activation.disarm();
        Ok(Transaction {
            producer: self,
            generation,
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

    fn activate_transaction(&self) -> Result<u64, KafkaError> {
        let mut state = self.state.lock();
        match state.phase {
            TransactionPhase::Idle => {
                state.generation = state.generation.checked_add(1).ok_or_else(|| {
                    KafkaError::Transaction("transaction generation exhausted".to_string())
                })?;
                state.phase = TransactionPhase::Active;
                state.abandoned = false;
                state.pending_offsets = None;
                #[cfg(all(not(feature = "kafka"), any(test, feature = "test-internals")))]
                state.staged_records.clear();
                Ok(state.generation)
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

    fn ensure_active_transaction(&self, generation: u64) -> Result<(), KafkaError> {
        let state = self.state.lock();
        if state.generation != generation {
            return Err(KafkaError::Transaction(
                "stale transaction owner".to_string(),
            ));
        }
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

    #[cfg(any(not(feature = "kafka"), test))]
    fn mark_transaction_idle(&self, generation: u64) {
        let mut state = self.state.lock();
        if state.generation != generation || state.operation_in_flight {
            return;
        }
        state.phase = TransactionPhase::Idle;
        state.pending_offsets = None;
        #[cfg(all(not(feature = "kafka"), any(test, feature = "test-internals")))]
        state.staged_records.clear();
    }

    fn mark_transaction_dropped(&self, generation: u64) {
        let mut state = self.state.lock();
        if state.generation != generation {
            return;
        }
        if state.operation_in_flight {
            state.abandoned = true;
            return;
        }
        if matches!(
            state.phase,
            TransactionPhase::Active | TransactionPhase::Finalizing
        ) {
            state.phase = TransactionPhase::NeedsAbortRecovery;
            state.pending_offsets = None;
            #[cfg(all(not(feature = "kafka"), any(test, feature = "test-internals")))]
            state.staged_records.clear();
        }
    }

    #[cfg(feature = "kafka")]
    async fn ensure_initialized(&self, cx: &Cx) -> Result<(), KafkaError> {
        let operation = {
            let mut state = self.state.lock();
            if state.initialized {
                return Ok(());
            }
            if state.operation_in_flight || state.phase != TransactionPhase::Idle {
                return Err(KafkaError::Transaction(
                    "transaction finalization in progress".to_string(),
                ));
            }
            state.operation_in_flight = true;
            state.phase = TransactionPhase::Finalizing;
            TransactionOperationGuard {
                state: Arc::clone(&self.state),
                generation: state.generation,
                operation: TransactionOperation::Initialize,
                offsets: None,
                started: false,
                completed: false,
            }
        };
        let producer = self.producer.clone();
        let timeout = self.config.transaction_timeout;
        run_owned_transaction_op(cx, operation, move || {
            producer
                .init_transactions(timeout)
                .map_err(|err| map_rdkafka_error(&err, None))
        })
        .await
    }

    #[cfg(not(feature = "kafka"))]
    #[allow(clippy::unused_async)]
    async fn ensure_initialized(&self, _cx: &Cx) -> Result<(), KafkaError> {
        Ok(())
    }

    fn claim_recovery(&self) -> Option<TransactionOperationGuard> {
        let mut state = self.state.lock();
        if state.phase != TransactionPhase::NeedsAbortRecovery {
            return None;
        }
        // Claim before releasing the lock; another begin must not queue a
        // second abort or reuse this producer before recovery completes.
        state.phase = TransactionPhase::Finalizing;
        state.operation_in_flight = true;
        Some(TransactionOperationGuard {
            state: Arc::clone(&self.state),
            generation: state.generation,
            operation: TransactionOperation::Recover,
            offsets: None,
            #[cfg(any(feature = "kafka", test))]
            started: false,
            completed: false,
        })
    }

    #[allow(clippy::unused_async)]
    async fn recover_abandoned_transaction(&self, cx: &Cx) -> Result<(), KafkaError> {
        let Some(operation) = self.claim_recovery() else {
            return Ok(());
        };

        #[cfg(not(feature = "kafka"))]
        let _ = cx;

        #[cfg(feature = "kafka")]
        return run_owned_transaction_op(cx, operation, {
            let producer = self.producer.clone();
            let timeout = self.config.transaction_timeout;
            move || {
                producer.abort_transaction(timeout).map_err(|err| {
                    // A fenced producer must be recreated. Keep that verdict
                    // instead of reporting a retryable broker error forever.
                    let fatal =
                        matches!(&err, RdKafkaError::Transaction(native) if native.is_fatal());
                    if fatal {
                        map_transaction_failure(err)
                    } else {
                        map_rdkafka_error(&err, None)
                    }
                })
            }
        })
        .await;

        #[cfg(not(feature = "kafka"))]
        operation.complete(Ok(()))
    }

    fn needs_abort_recovery(&self, generation: u64) -> bool {
        let state = self.state.lock();
        state.generation == generation && state.phase == TransactionPhase::NeedsAbortRecovery
    }
}

#[derive(Clone, Copy)]
enum TransactionOperation {
    #[cfg(feature = "kafka")]
    Initialize,
    #[cfg(any(feature = "kafka", test))]
    Begin,
    #[cfg(any(feature = "kafka", test))]
    Finalize,
    #[cfg(any(feature = "kafka", test))]
    SendOffsets,
    #[cfg(any(feature = "kafka", test))]
    Commit,
    Recover,
}

/// Owns the occupied phase even if the async waiter disappears. Its Drop also
/// covers a queued closure that is discarded, submission failure, and panic.
struct TransactionOperationGuard {
    state: Arc<Mutex<TransactionalProducerState>>,
    generation: u64,
    operation: TransactionOperation,
    #[cfg_attr(not(any(feature = "kafka", test)), allow(dead_code))]
    offsets: Option<PreparedTransactionOffsets>,
    #[cfg(any(feature = "kafka", test))]
    started: bool,
    completed: bool,
}

impl TransactionOperationGuard {
    #[cfg(any(feature = "kafka", test))]
    fn claim(
        owner: &Arc<Mutex<TransactionalProducerState>>,
        generation: u64,
        operation: TransactionOperation,
    ) -> Result<Self, KafkaError> {
        let mut state = owner.lock();
        let expected = match operation {
            TransactionOperation::Recover => TransactionPhase::NeedsAbortRecovery,
            #[cfg(feature = "kafka")]
            TransactionOperation::Initialize => TransactionPhase::Idle,
            TransactionOperation::Begin
            | TransactionOperation::Finalize
            | TransactionOperation::SendOffsets
            | TransactionOperation::Commit => {
                TransactionPhase::Active
            }
        };
        if state.generation != generation || state.operation_in_flight || state.phase != expected {
            return Err(KafkaError::Transaction(
                "transaction finalization in progress".to_string(),
            ));
        }
        state.operation_in_flight = true;
        state.phase = TransactionPhase::Finalizing;
        Ok(Self {
            state: Arc::clone(owner),
            generation,
            operation,
            offsets: None,
            started: false,
            completed: false,
        })
    }

    #[cfg(any(feature = "kafka", test))]
    fn claim_offsets(
        owner: &Arc<Mutex<TransactionalProducerState>>,
        generation: u64,
        offsets: PreparedTransactionOffsets,
    ) -> Result<Self, KafkaError> {
        let mut state = owner.lock();
        if state.generation != generation
            || state.operation_in_flight
            || state.phase != TransactionPhase::Active
        {
            return Err(KafkaError::Transaction("transaction is not active".into()));
        }
        // Validate the whole new enrollment before claiming any native effect.
        // A bad second batch leaves the already-enrolled transaction intact.
        let offsets = if let Some(previous) = &state.pending_offsets {
            previous.merge(&offsets)?
        } else {
            offsets
        };
        state.operation_in_flight = true;
        state.phase = TransactionPhase::Finalizing;
        Ok(Self {
            state: Arc::clone(owner),
            generation,
            operation: TransactionOperation::SendOffsets,
            offsets: Some(offsets),
            started: false,
            completed: false,
        })
    }

    fn complete(mut self, result: Result<(), KafkaError>) -> Result<(), KafkaError> {
        #[allow(unused_mut)]
        let mut committed_offsets: Option<PreparedTransactionOffsets> = None;
        {
            let mut state = self.state.lock();
            if state.generation == self.generation && state.operation_in_flight {
                state.phase = match self.operation {
                    #[cfg(feature = "kafka")]
                    TransactionOperation::Initialize => {
                        state.initialized = result.is_ok();
                        TransactionPhase::Idle
                    }
                    #[cfg(any(feature = "kafka", test))]
                    TransactionOperation::Begin | TransactionOperation::SendOffsets
                        if result.is_ok() =>
                    {
                        if state.abandoned {
                            TransactionPhase::NeedsAbortRecovery
                        } else {
                            TransactionPhase::Active
                        }
                    }
                    #[cfg(any(feature = "kafka", test))]
                    TransactionOperation::Begin => TransactionPhase::Idle,
                    _ if result.is_ok() => TransactionPhase::Idle,
                    _ => TransactionPhase::NeedsAbortRecovery,
                };
                #[cfg(any(feature = "kafka", test))]
                if matches!(self.operation, TransactionOperation::SendOffsets)
                    && state.phase == TransactionPhase::Active
                {
                    state.pending_offsets = self.offsets.take();
                }
                #[cfg(any(feature = "kafka", test))]
                if matches!(self.operation, TransactionOperation::Commit) && result.is_ok() {
                    committed_offsets = state.pending_offsets.take();
                }
                if state.phase != TransactionPhase::Active {
                    state.pending_offsets = None;
                }
                if committed_offsets.is_some() {
                    // Keep admission fenced until the matching consumer cache
                    // has caught up with the acknowledged broker commit.
                    state.phase = TransactionPhase::Finalizing;
                } else {
                    state.operation_in_flight = false;
                }
                #[cfg(all(not(feature = "kafka"), any(test, feature = "test-internals")))]
                if state.phase != TransactionPhase::Active {
                    state.staged_records.clear();
                }
            }
        }
        // Never acquire consumer state while holding producer state: metadata
        // validation and transaction admission take these locks independently.
        // Publication runs on the native worker even if its async waiter left.
        if let Some(offsets) = committed_offsets {
            offsets.publish_committed();
            let mut state = self.state.lock();
            if state.generation == self.generation && state.operation_in_flight {
                state.phase = TransactionPhase::Idle;
                state.operation_in_flight = false;
            }
        }
        self.completed = true;
        result
    }
}

impl Drop for TransactionOperationGuard {
    fn drop(&mut self) {
        if self.completed {
            return;
        }
        let mut state = self.state.lock();
        if state.generation != self.generation || !state.operation_in_flight {
            return;
        }
        state.operation_in_flight = false;
        state.phase = match self.operation {
            #[cfg(feature = "kafka")]
            TransactionOperation::Initialize => TransactionPhase::Idle,
            #[cfg(any(feature = "kafka", test))]
            TransactionOperation::Begin if !self.started => TransactionPhase::Idle,
            _ => TransactionPhase::NeedsAbortRecovery,
        };
        state.pending_offsets = None;
    }
}

#[cfg(any(feature = "kafka", test))]
async fn run_owned_transaction_op<F>(
    cx: &Cx,
    mut operation: TransactionOperationGuard,
    f: F,
) -> Result<(), KafkaError>
where
    F: FnOnce() -> Result<(), KafkaError> + Send + 'static,
{
    run_kafka_blocking(cx, move || {
        operation.started = true;
        let result = f();
        operation.complete(result)
    })
    .await
}

/// RAII guard for the `activate_transaction()`→`Transaction` handoff window in
/// `begin_transaction` (br-asupersync-tx3wq9).
///
/// While armed, its `Drop` marks its generation abandoned. An in-flight
/// operation keeps ownership until completion; otherwise an Active generation
/// moves to NeedsAbortRecovery.
/// `begin_transaction` disarms it on both the error and success paths, so the
/// guard fires only when the `begin` future is dropped mid-flight (cancellation)
/// before either path runs — the case that previously wedged the phase in
/// `Active`. This mirrors [`Transaction`]'s own `Drop`.
struct TransactionActivationGuard<'a> {
    producer: Option<&'a TransactionalProducer>,
    generation: u64,
}

impl<'a> TransactionActivationGuard<'a> {
    fn armed(producer: &'a TransactionalProducer) -> Self {
        Self {
            producer: Some(producer),
            generation: producer.state.lock().generation,
        }
    }

    fn disarm(&mut self) {
        self.producer = None;
    }
}

impl Drop for TransactionActivationGuard<'_> {
    fn drop(&mut self) {
        if let Some(producer) = self.producer {
            producer.mark_transaction_dropped(self.generation);
        }
    }
}

/// An active Kafka transaction.
///
/// Messages sent within a transaction are atomically committed or aborted.
/// The transaction must be explicitly committed or aborted before being dropped.
#[derive(Debug)]
pub struct Transaction<'a> {
    producer: &'a TransactionalProducer,
    generation: u64,
    finished: bool,
}

impl Transaction<'_> {
    /// Send a message within the transaction.
    pub async fn send(
        &self,
        cx: &Cx,
        topic: &str,
        key: Option<&[u8]>,
        payload: &[u8],
    ) -> Result<(), KafkaError> {
        self.send_nullable(cx, topic, key, Some(payload)).await
    }

    /// Send a nullable value within the transaction.
    ///
    /// A keyed `None` payload is a compaction tombstone; `Some(&[])` is an
    /// empty value. The tombstone participates in this transaction's normal
    /// commit/abort boundary, including any enrolled consumer offsets. Observe
    /// transaction isolation with a `read_committed` consumer.
    pub async fn send_nullable(
        &self,
        cx: &Cx,
        topic: &str,
        key: Option<&[u8]>,
        payload: Option<&[u8]>,
    ) -> Result<(), KafkaError> {
        self.send_request(
            cx,
            SendRequest {
                topic,
                key,
                payload,
                partition: None,
                headers: SendHeaders::None,
            },
        )
        .await
    }

    /// Send a nullable value and ordered nullable headers in this transaction.
    /// Duplicate names and null versus empty header values are retained.
    pub async fn send_nullable_with_headers(
        &self,
        cx: &Cx,
        topic: &str,
        key: Option<&[u8]>,
        payload: Option<&[u8]>,
        headers: &[(&str, Option<&[u8]>)],
    ) -> Result<(), KafkaError> {
        self.send_request(
            cx,
            SendRequest {
                topic,
                key,
                payload,
                partition: None,
                headers: SendHeaders::Nullable(headers),
            },
        )
        .await
    }

    #[allow(clippy::unused_async)]
    async fn send_request(&self, cx: &Cx, request: SendRequest<'_>) -> Result<(), KafkaError> {
        cx.checkpoint().map_err(|_| KafkaError::Cancelled)?;
        self.producer.ensure_active_transaction(self.generation)?;
        validate_topic(request.topic)?;

        let payload_size = request.payload.map_or(0, <[u8]>::len);
        if payload_size > self.producer.config.producer.max_message_size {
            return Err(KafkaError::MessageTooLarge {
                size: payload_size,
                max_size: self.producer.config.producer.max_message_size,
            });
        }

        #[cfg(feature = "kafka")]
        {
            send_with_producer(
                &self.producer.producer,
                cx,
                &self.producer.config.producer,
                request,
            )
            .await
            .map(|_metadata| ())
        }

        #[cfg(all(not(feature = "kafka"), any(test, feature = "test-internals")))]
        {
            let mut state = self.producer.state.lock();
            if state.phase != TransactionPhase::Active || state.generation != self.generation {
                return Err(KafkaError::Transaction(
                    "transaction is not available for sends".to_string(),
                ));
            }
            state.staged_records.push(DeterministicBrokerRecord {
                topic: request.topic.to_string(),
                partition: 0,
                key: request.key.map(std::borrow::ToOwned::to_owned),
                payload: request.payload.map(std::borrow::ToOwned::to_owned),
                timestamp: None,
                headers: request.headers.iter()
                    .map(|(key, value)| (key.to_owned(), value.map(std::borrow::ToOwned::to_owned)))
                    .collect(),
            });
            drop(state);
            Ok(())
        }
        #[cfg(all(not(feature = "kafka"), not(any(test, feature = "test-internals"))))]
        {
            Err(KafkaError::FeatureDisabled)
        }
    }

    /// Enroll consumed offsets in this producer transaction.
    ///
    /// Each offset is the next record to consume, usually the last processed
    /// offset plus one. Capture `metadata` with
    /// [`super::kafka_consumer::KafkaConsumer::group_metadata`] after polling.
    /// Automatic consumer commits must be disabled, and the application must
    /// not separately commit these offsets. Output records and enrolled offsets
    /// become committed only when [`Self::commit`] succeeds at the broker.
    /// Aborting discards both. Read downstream output with `read_committed`.
    ///
    /// Repeated calls may advance offsets or add assigned partitions using the
    /// same metadata snapshot (or a clone). They cannot regress an enrolled
    /// offset, switch groups, or replace the membership snapshot mid-transaction.
    /// Capture a new snapshot after a rebalance and begin a new transaction. A
    /// refused replacement after the enrolled snapshot went stale requires
    /// abort recovery, like enrolling a stale snapshot directly.
    ///
    /// The bounded native call runs on the existing blocking executor. A dropped
    /// waiter does not stop librdkafka: the producer remains occupied until the
    /// actual native completion, then requires abort recovery before reuse.
    /// An enrollment error also requires abort recovery. Drop this transaction
    /// and use [`TransactionalProducer::begin_transaction`] to perform that
    /// recovery; a fatal/fenced producer must be recreated if recovery fails.
    /// Input validation errors before enrollment (an empty, duplicate,
    /// regressing or unassigned offset) leave the transaction usable. A
    /// snapshot whose consumer was closed, dropped or rebalanced requires abort
    /// recovery, because this transaction can never enroll its offsets.
    ///
    /// Without the `kafka` feature this operation always returns
    /// [`KafkaError::FeatureDisabled`], including deterministic broker harnesses.
    #[allow(unused_variables, clippy::unused_async)]
    pub async fn send_offsets_to_transaction(
        &self,
        cx: &Cx,
        offsets: &[TopicPartitionOffset],
        metadata: &ConsumerGroupMetadata,
    ) -> Result<(), KafkaError> {
        cx.checkpoint().map_err(|_| KafkaError::Cancelled)?;
        self.producer.ensure_active_transaction(self.generation)?;

        #[cfg(feature = "kafka")]
        {
            metadata.native()?;
            let offsets = match metadata.prepare_offsets(offsets) {
                Ok(offsets) => offsets,
                Err(error) => {
                    // A stale, closed or dropped consumer can never enroll
                    // offsets in this transaction. Committing it without them
                    // would publish the output while the input is re-read
                    // after a restart, so it now requires abort recovery, as
                    // the in-worker membership check already does
                    // (br-asupersync-csyp1h). Input-shape errors stay local.
                    if metadata.check_membership().is_err() {
                        self.producer.mark_transaction_dropped(self.generation);
                    }
                    return Err(error);
                }
            };
            let operation = match TransactionOperationGuard::claim_offsets(
                &self.producer.state,
                self.generation,
                offsets,
            ) {
                Ok(operation) => operation,
                Err(error) => {
                    // A refused enrollment, such as a switch to a fresh snapshot
                    // after a rebalance, leaves only the already-enrolled offsets.
                    // If that snapshot has gone stale they can never be completed,
                    // so committing would publish output without its input
                    // offsets (br-asupersync-y603m5). Read the snapshot outside
                    // the producer lock before checking the consumer's state.
                    let enrolled = self
                        .producer
                        .state
                        .lock()
                        .pending_offsets
                        .as_ref()
                        .map(|pending| pending.metadata.clone());
                    if enrolled.is_some_and(|enrolled| enrolled.check_membership().is_err()) {
                        self.producer.mark_transaction_dropped(self.generation);
                    }
                    return Err(error);
                }
            };
            let offsets = operation.offsets.as_ref().expect("claimed offset enrollment").clone();
            let producer = self.producer.producer.clone();
            let timeout = self.producer.config.transaction_timeout;
            // This also covers native success before a completed waiter is
            // dropped without observing its result. A stale guard cannot poison
            // a later transaction generation.
            let mut enrollment = TransactionActivationGuard::armed(self.producer);
            let result = run_owned_transaction_op(cx, operation, move || {
                offsets.validate_current()?;
                let mut partitions = rdkafka::topic_partition_list::TopicPartitionList::new();
                for ((topic, partition), offset) in &offsets.offsets {
                    partitions
                        .add_partition_offset(
                            topic,
                            *partition,
                            rdkafka::topic_partition_list::Offset::Offset(*offset),
                        )
                        .map_err(|error| map_rdkafka_error(&error, None))?;
                }
                producer
                    .send_offsets_to_transaction(&partitions, offsets.metadata.native()?, timeout)
                    .map_err(map_transaction_failure)
            })
            .await;
            enrollment.disarm();
            result
        }
        #[cfg(not(feature = "kafka"))]
        {
            Err(KafkaError::FeatureDisabled)
        }
    }

    /// Commit the transaction.
    ///
    /// Atomically publishes all messages and consumer offsets enrolled in this
    /// transaction. The consumer's local offset cache changes only after native
    /// success, and only if its captured assignment is still current.
    /// Once the broker operation starts, dropping this future does not undo it.
    /// The producer remains occupied until background completion; cancellation
    /// is not evidence that the transaction was aborted.
    ///
    /// When librdkafka reports the commit as retriable (it did not finish
    /// within `transaction_timeout`), the commit is resumed up to three more
    /// times, each bounded by `transaction_timeout`, before the error is
    /// returned. After a returned retriable error the commit outcome is
    /// unknown.
    #[allow(unused_variables, clippy::unused_async)]
    pub async fn commit(mut self, cx: &Cx) -> Result<(), KafkaError> {
        cx.checkpoint().map_err(|_| KafkaError::Cancelled)?;
        self.producer.ensure_active_transaction(self.generation)?;

        #[cfg(feature = "kafka")]
        {
            let enrolled_offsets = self.producer.state.lock().pending_offsets.is_some();
            let operation = TransactionOperationGuard::claim(
                &self.producer.state,
                self.generation,
                TransactionOperation::Commit,
            )?;
            self.finished = true; // The operation guard now owns cleanup.
            run_owned_transaction_op(cx, operation, {
                let producer = self.producer.producer.clone();
                let timeout = self.producer.config.transaction_timeout;
                move || {
                    commit_resuming_retriable_failures(|| producer.commit_transaction(timeout))
                        .map_err(|error| {
                            if enrolled_offsets {
                                map_transaction_failure(error)
                            } else {
                                map_rdkafka_error(&error, None)
                            }
                        })
                }
            })
            .await?;
        }

        #[cfg(all(not(feature = "kafka"), any(test, feature = "test-internals")))]
        {
            let staged = {
                let mut state = self.producer.state.lock();
                if state.phase != TransactionPhase::Active || state.generation != self.generation {
                    return Err(KafkaError::Transaction(
                        "transaction is not active".to_string(),
                    ));
                }
                state.phase = TransactionPhase::Finalizing;
                std::mem::take(&mut state.staged_records)
            };

            let _metadata = deterministic_broker_publish_batch(staged);
            self.producer.mark_transaction_idle(self.generation);
            self.finished = true;
        }
        #[cfg(all(not(feature = "kafka"), not(any(test, feature = "test-internals"))))]
        {
            self.producer.mark_transaction_idle(self.generation);
            self.finished = true;
            Err(KafkaError::FeatureDisabled)
        }

        #[cfg(any(feature = "kafka", test, feature = "test-internals"))]
        {
            Ok(())
        }
    }

    /// Abort the transaction.
    ///
    /// Discards all messages sent within this transaction.
    /// Once the broker operation starts, dropping this future does not undo it.
    /// The producer remains occupied until the background abort completes.
    #[allow(unused_variables, clippy::unused_async)]
    pub async fn abort(mut self, cx: &Cx) -> Result<(), KafkaError> {
        cx.checkpoint().map_err(|_| KafkaError::Cancelled)?;
        // A failed enrollment or commit left this transaction needing abort
        // recovery, which is this abort. Run it now instead of leaving the
        // broker transaction open until the next begin or its timeout.
        if self.producer.needs_abort_recovery(self.generation) {
            self.finished = true;
            return self.producer.recover_abandoned_transaction(cx).await;
        }
        self.producer.ensure_active_transaction(self.generation)?;

        #[cfg(feature = "kafka")]
        {
            let operation = TransactionOperationGuard::claim(
                &self.producer.state,
                self.generation,
                TransactionOperation::Finalize,
            )?;
            self.finished = true;
            run_owned_transaction_op(cx, operation, {
                let producer = self.producer.producer.clone();
                let timeout = self.producer.config.transaction_timeout;
                move || {
                    producer
                        .abort_transaction(timeout)
                        .map_err(|err| map_rdkafka_error(&err, None))
                }
            })
            .await?;
        }

        #[cfg(not(feature = "kafka"))]
        {
            self.producer.mark_transaction_idle(self.generation);
            self.finished = true;
        }

        Ok(())
    }
}

impl Drop for Transaction<'_> {
    fn drop(&mut self) {
        if !self.finished {
            self.producer.mark_transaction_dropped(self.generation);
        }
    }
}

/// Broker backend abstraction for switching between real and deterministic implementations.
pub trait BrokerBackend: Send + Sync {
    /// Check if this backend supports real broker integration.
    fn is_real_broker(&self) -> bool;

    /// Get backend type description for diagnostics.
    fn backend_type(&self) -> &'static str;
}

/// Real Kafka broker backend using rdkafka.
#[cfg(feature = "kafka")]
pub struct RealBrokerBackend;

#[cfg(feature = "kafka")]
impl BrokerBackend for RealBrokerBackend {
    fn is_real_broker(&self) -> bool {
        true
    }
    fn backend_type(&self) -> &'static str {
        "rdkafka"
    }
}

/// Deterministic broker backend for crate-local tests and offline diagnostics.
#[cfg(not(feature = "kafka"))]
pub struct DeterministicBrokerBackend;

#[cfg(not(feature = "kafka"))]
impl BrokerBackend for DeterministicBrokerBackend {
    fn is_real_broker(&self) -> bool {
        false
    }
    fn backend_type(&self) -> &'static str {
        "deterministic"
    }
}

/// Consumer abstraction for switching between real and deterministic implementations.
pub trait KafkaConsumerTrait: Send + Sync {
    /// Get the topic this consumer is subscribed to.
    fn topic(&self) -> &str;

    /// Check if this consumer is connected to a real broker.
    fn is_real_consumer(&self) -> bool;

    /// Get consumer type description for diagnostics.
    fn consumer_type(&self) -> &'static str;
}

/// Wrapper around rdkafka BaseConsumer that tracks the topic name.
#[cfg(feature = "kafka")]
pub struct TopicAwareConsumer {
    consumer: BaseConsumer<KafkaContext>,
    topic: String,
}

/// Real Kafka consumer backend using rdkafka BaseConsumer with topic tracking.
#[cfg(feature = "kafka")]
impl KafkaConsumerTrait for TopicAwareConsumer {
    fn topic(&self) -> &str {
        &self.topic
    }

    fn is_real_consumer(&self) -> bool {
        true
    }

    fn consumer_type(&self) -> &'static str {
        "rdkafka::BaseConsumer"
    }
}

/// Unified Kafka client combining producer and consumer capabilities.
///
/// This is a high-level wrapper around `KafkaProducer` and rdkafka's
/// `BaseConsumer` to provide a single entry point for Kafka operations.
/// Automatically selects between real broker integration (when available)
/// and deterministic broker (for testing).
///
/// # Example
///
/// ```rust,ignore
/// let client = KafkaClient::new(config).await?;
/// let producer = client.producer();
/// let consumer = client.consumer(topic).await?;
/// ```
#[cfg(feature = "kafka")]
pub struct KafkaClient {
    producer: KafkaProducer,
    consumer: Option<TopicAwareConsumer>,
    config: ProducerConfig,
    backend: Box<dyn BrokerBackend>,
}

#[cfg(feature = "kafka")]
fn create_kafka_client_consumer(
    config: &ClientConfig,
) -> Result<BaseConsumer<KafkaContext>, KafkaError> {
    config.create_with_context(KafkaContext).map_err(|error| {
        let message = match error {
            RdKafkaError::ClientConfig(result, _, key, _) => redacted_config_message(result, &key),
            _ => error.to_string(),
        };
        KafkaError::Config(format!("Failed to create consumer: {message}"))
    })
}

#[cfg(feature = "kafka")]
impl KafkaClient {
    /// Create a new unified Kafka client with real broker backend.
    pub async fn new(config: ProducerConfig) -> Result<Self, KafkaError> {
        let producer = KafkaProducer::new(config.clone())?;
        Ok(Self {
            producer,
            consumer: None,
            config,
            backend: Box::new(RealBrokerBackend),
        })
    }

    /// Get the producer for publishing messages.
    pub fn producer(&self) -> &KafkaProducer {
        &self.producer
    }

    /// Get broker backend information.
    pub fn backend(&self) -> &dyn BrokerBackend {
        self.backend.as_ref()
    }

    /// Initialize consumer for the given topic.
    pub async fn consumer(&mut self, topic: &str) -> Result<&dyn KafkaConsumerTrait, KafkaError> {
        let group_id = kafka_client_consumer_group_id(&self.config, topic)?;

        if let Some(ref consumer) = self.consumer {
            let _ = &consumer.consumer;
            // Validate existing consumer is for the requested topic
            if consumer.topic() != topic {
                return Err(KafkaError::Config(format!(
                    "Consumer already exists for topic '{}', cannot create consumer for different topic '{}'",
                    consumer.topic(),
                    topic
                )));
            }
            return Ok(consumer);
        }

        // Create consumer config based on producer config
        let mut consumer_config = ClientConfig::new();
        consumer_config.set("bootstrap.servers", self.config.bootstrap_servers.join(","));
        apply_security_config(&mut consumer_config, &self.config.security);
        consumer_config.set("group.id", &group_id);
        if let Some(client_id) = &self.config.client_id {
            consumer_config.set("client.id", client_id);
        }
        consumer_config.set("enable.partition.eof", "false");
        consumer_config.set("session.timeout.ms", "6000");
        // br-asupersync-2i2e21: default is manual-commit / at-least-once.
        // The polling driver stores the offset at poll time when this is
        // on, which silently turns at-least-once into at-most-once.
        // Callers that want auto-commit must build a consumer through
        // `ConsumerConfig::enable_auto_commit(true)` deliberately.
        consumer_config.set("enable.auto.commit", "false");

        // Create BaseConsumer
        let rdkafka_consumer = create_kafka_client_consumer(&consumer_config)?;

        // Subscribe to the topic
        rdkafka_consumer.subscribe(&[topic]).map_err(|e| {
            KafkaError::Config(format!("Failed to subscribe to topic {}: {}", topic, e))
        })?;

        // Wrap in TopicAwareConsumer
        self.consumer = Some(TopicAwareConsumer {
            consumer: rdkafka_consumer,
            topic: topic.to_string(),
        });

        let consumer = self.consumer.as_ref().unwrap();
        let _ = &consumer.consumer;
        Ok(consumer)
    }
}

/// Deterministic consumer for crate-local tests when the kafka feature is disabled.
#[cfg(all(not(feature = "kafka"), test))]
pub struct DeterministicConsumer {
    topic: String,
}

/// Deterministic Kafka consumer backend.
#[cfg(all(not(feature = "kafka"), test))]
impl KafkaConsumerTrait for DeterministicConsumer {
    fn topic(&self) -> &str {
        &self.topic
    }

    fn is_real_consumer(&self) -> bool {
        false
    }

    fn consumer_type(&self) -> &'static str {
        "deterministic"
    }
}

/// Deterministic-harness version of KafkaClient when kafka feature is disabled.
#[cfg(not(feature = "kafka"))]
pub struct KafkaClient {
    producer: KafkaProducer,
    #[cfg(test)]
    consumer: Option<DeterministicConsumer>,
    backend: Box<dyn BrokerBackend>,
}

#[cfg(not(feature = "kafka"))]
impl KafkaClient {
    /// Create a new unified Kafka client with deterministic broker backend.
    pub async fn new(config: ProducerConfig) -> Result<Self, KafkaError> {
        let producer = KafkaProducer::new(config.clone())?;
        Ok(Self {
            producer,
            #[cfg(test)]
            consumer: None,
            backend: Box::new(DeterministicBrokerBackend),
        })
    }

    /// Get the producer for publishing messages.
    pub fn producer(&self) -> &KafkaProducer {
        &self.producer
    }

    /// Get broker backend information.
    pub fn backend(&self) -> &dyn BrokerBackend {
        self.backend.as_ref()
    }

    /// Initialize consumer for the given topic.
    pub async fn consumer(&mut self, topic: &str) -> Result<&dyn KafkaConsumerTrait, KafkaError> {
        validate_topic(topic)?;

        #[cfg(test)]
        {
            if let Some(ref consumer) = self.consumer {
                // Validate existing consumer is for the requested topic
                if consumer.topic() != topic {
                    return Err(KafkaError::Config(format!(
                        "Consumer already exists for topic '{}', cannot create consumer for different topic '{}'",
                        consumer.topic(),
                        topic
                    )));
                }
                return Ok(consumer);
            }

            // Crate-local tests may use the deterministic harness consumer, but
            // non-test builds without the kafka feature must fail loudly below.
            self.consumer = Some(DeterministicConsumer {
                topic: topic.to_string(),
            });
            Ok(self.consumer.as_ref().unwrap())
        }

        #[cfg(not(test))]
        {
            Err(KafkaError::FeatureDisabled)
        }
    }
}

// Fuzz functions for testing Kafka response frame parsing
#[cfg(any(test, fuzzing, feature = "fuzz"))]
impl From<u8> for Acks {
    fn from(value: u8) -> Self {
        match value {
            0 => Self::None,
            1 => Self::Leader,
            _ => Self::All,
        }
    }
}

#[cfg(any(test, fuzzing, feature = "fuzz"))]
impl From<u8> for Compression {
    fn from(value: u8) -> Self {
        match value % 4 {
            0 => Self::None,
            1 => Self::Gzip,
            2 => Self::Snappy,
            _ => Self::Lz4,
        }
    }
}

/// Fuzz function: parse Kafka error response from raw bytes
#[cfg(any(test, fuzzing, feature = "fuzz"))]
pub fn fuzz_parse_kafka_error_response(data: &[u8]) -> Result<KafkaError, String> {
    if data.is_empty() {
        return Ok(KafkaError::Protocol("empty response".to_string()));
    }

    // Parse the minimal error response frame structure used by fuzz corpora.
    let error_code = data[0] as i16;
    let has_message = data.len() > 1;

    let message = if has_message && data.len() > 2 {
        // Extract length prefix (2 bytes) + message
        let msg_len = if data.len() >= 3 {
            u16::from_be_bytes([data[1], data[2]]) as usize
        } else {
            0
        };

        if data.len() >= 3 + msg_len {
            String::from_utf8_lossy(&data[3..3 + msg_len]).to_string()
        } else {
            String::from_utf8_lossy(&data[3..]).to_string()
        }
    } else {
        "generic error".to_string()
    };

    // Map common Kafka error codes to KafkaError variants
    match error_code {
        0 => Ok(KafkaError::Protocol("no error".to_string())),
        1 => Ok(KafkaError::Protocol(message)),
        2..=10 => Ok(KafkaError::Broker(message)),
        11..=20 => Ok(KafkaError::InvalidTopic(message)),
        21..=30 => Ok(KafkaError::MessageTooLarge {
            size: (error_code as usize).saturating_mul(100),
            max_size: 1024 * 1024,
        }),
        31..=40 => Ok(KafkaError::Transaction(message)),
        41..=50 => Ok(KafkaError::QueueFull),
        51..=60 => Ok(KafkaError::Config(message)),
        61..=70 => Ok(KafkaError::Cancelled),
        _ => Ok(KafkaError::Protocol(format!(
            "unknown error code: {error_code}"
        ))),
    }
}

/// Fuzz function: parse Kafka response metadata from raw bytes
#[cfg(any(test, fuzzing, feature = "fuzz"))]
pub fn fuzz_parse_response_metadata(data: &[u8]) -> Result<RecordMetadata, String> {
    if data.len() < 16 {
        return Err("insufficient data for metadata".to_string());
    }

    // Parse response metadata frame:
    // bytes 0-7: offset (i64)
    // bytes 8-11: partition (i32)
    // bytes 12-15: timestamp_low (i32)
    // bytes 16+: topic name (length-prefixed string)

    let offset = i64::from_be_bytes([
        data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
    ]);

    let partition = i32::from_be_bytes([data[8], data[9], data[10], data[11]]);

    let timestamp_low = i32::from_be_bytes([data[12], data[13], data[14], data[15]]);
    let timestamp = if timestamp_low >= 0 {
        Some(i64::from(timestamp_low) * 1000) // Convert to millis
    } else {
        None
    };

    let topic = if data.len() > 16 {
        if data.len() >= 18 {
            let topic_len = u16::from_be_bytes([data[16], data[17]]) as usize;
            if data.len() >= 18 + topic_len {
                String::from_utf8_lossy(&data[18..18 + topic_len]).to_string()
            } else {
                String::from_utf8_lossy(&data[18..]).to_string()
            }
        } else {
            "default".to_string()
        }
    } else {
        "default".to_string()
    };

    // Validate parsed values
    if partition < 0 {
        return Err(format!("negative partition: {partition}"));
    }

    if offset < 0 {
        return Err(format!("negative offset: {offset}"));
    }

    if topic.is_empty() {
        return Err("empty topic name".to_string());
    }

    Ok(RecordMetadata {
        topic,
        partition,
        offset,
        timestamp,
    })
}

/// Fuzz function: validate Kafka response frame structure
#[cfg(any(test, fuzzing, feature = "fuzz"))]
pub fn fuzz_validate_response_frame(data: &[u8]) -> Result<(), String> {
    if data.len() < 8 {
        return Err("response frame too short".to_string());
    }

    // Parse frame header:
    // bytes 0-3: correlation_id (i32)
    // bytes 4-7: response_length (i32)

    let correlation_id = i32::from_be_bytes([data[0], data[1], data[2], data[3]]);
    let response_length = i32::from_be_bytes([data[4], data[5], data[6], data[7]]);

    // Validate correlation ID is reasonable
    if !(0..=1_000_000).contains(&correlation_id) {
        return Err(format!("invalid correlation_id: {correlation_id}"));
    }

    // Validate response length
    if response_length < 0 {
        return Err(format!("negative response_length: {response_length}"));
    }

    if response_length > 50 * 1024 * 1024 {
        // 50MB limit
        return Err(format!("response_length too large: {response_length}"));
    }

    // Check if declared length matches remaining data
    let expected_total = 8 + response_length as usize;
    if data.len() != expected_total {
        return Err(format!(
            "length mismatch: declared {expected_total}, actual {}",
            data.len()
        ));
    }

    // Basic response payload validation
    if response_length > 0 && data.len() > 8 {
        let payload = &data[8..];

        // Check for basic response structure markers
        if payload.is_empty() {
            return Err("empty response payload".to_string());
        }

        // Simple validation: first byte should be reasonable API version/error code
        let first_byte = payload[0];
        if first_byte > 100 {
            return Err(format!("suspicious first response byte: {first_byte}"));
        }
    }

    Ok(())
}

/// Fuzz function: parse Kafka delivery result from response
#[cfg(any(test, fuzzing, feature = "fuzz"))]
pub fn fuzz_parse_delivery_result(data: &[u8]) -> Result<RecordMetadata, KafkaError> {
    // First validate the frame
    fuzz_validate_response_frame(data)
        .map_err(|e| KafkaError::Protocol(format!("frame validation failed: {e}")))?;

    if data.len() < 12 {
        return Err(KafkaError::Protocol(
            "insufficient data for delivery result".to_string(),
        ));
    }

    // Skip correlation_id and response_length (8 bytes), parse result
    let payload = &data[8..];

    // Check for error indicator (first byte)
    if payload[0] != 0 {
        let error_code = payload[0];
        let kafka_error =
            fuzz_parse_kafka_error_response(&[error_code]).map_err(KafkaError::Protocol)?;
        return Err(kafka_error);
    }

    // Parse successful delivery result from remaining payload
    if payload.len() < 4 {
        return Err(KafkaError::Protocol(
            "incomplete delivery result".to_string(),
        ));
    }

    fuzz_parse_response_metadata(&payload[1..])
        .map_err(|e| KafkaError::Protocol(format!("metadata parse failed: {e}")))
}

#[cfg(test)]
#[path = "kafka_inline_tests.rs"]
mod tests;
